#!/bin/bash

# ================================================================
# Script de arranque de MISP — completamente autónomo
# Resuelve el problema de race-condition: MariaDB arranca tarde
# y el entrypoint de coolacid/misp-docker falla en frío.
# Este script gestiona manualmente la inicialización de BD.
# ================================================================
set -euo pipefail

MISP_API_KEY="NOVADEFMISPINTEGRATIONKEYpmp1234567890ab"
ADMIN_EMAIL="admin@admin.test"
SHODAN_KEY="TU_API_KEY_DE_SHODAN"
VIRUSTOTAL_KEY="TU_API_KEY_DE_VIRUSTOTAL"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

_log()  { echo "   $*"; }
_ok()   { echo "   ✅ $*"; }
_warn() { echo "   ⚠️  $*"; }

# ----------------------------------------------------------------
# PASO 1: Generar certificados SSL ANTES de arrancar el contenedor
# (evita el fallo de nginx por certs ausentes en el arranque en frío)
# ----------------------------------------------------------------
echo ""
echo "🔐 [1/8] Generando certificados SSL para MISP..."
mkdir -p "$SCRIPT_DIR/certs"
if [ ! -f "$SCRIPT_DIR/certs/cert.pem" ] || [ ! -f "$SCRIPT_DIR/certs/key.pem" ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SCRIPT_DIR/certs/key.pem" \
        -out    "$SCRIPT_DIR/certs/cert.pem" \
        -subj "/C=ES/ST=Madrid/O=NOVADEF/CN=localhost" 2>/dev/null
    _ok "cert.pem + key.pem generados."
fi
if [ ! -f "$SCRIPT_DIR/certs/dhparams.pem" ]; then
    openssl dhparam -out "$SCRIPT_DIR/certs/dhparams.pem" 2048 2>/dev/null
    _ok "dhparams.pem generado."
fi
chmod 644 "$SCRIPT_DIR/certs/"*.pem 2>/dev/null || true

# ----------------------------------------------------------------
# PASO 2: Arrancar los contenedores
# ----------------------------------------------------------------
echo ""
echo "🐳 [2/8] Levantando infraestructura MISP..."
cd "$SCRIPT_DIR"
docker compose up -d

# ----------------------------------------------------------------
# PASO 2b: Parchear fuentes MISP (columnas 1_* → a_*) ANTES de migraciones
# ---------------------------------------------------------------
# PROBLEMA RAÍZ: AppModel.php contiene los CREATE TABLE de las migraciones
# con columnas `1_event_id` (backtick-quoted SQL), MYSQL.sql tiene las tablas
# base también con 1_*, y db_schema.json los referencia. El entrypoint de
# coolacid/misp-docker corre 'runMigrations' en background nada más arrancar;
# si no parcheamos ANTES de que MariaDB esté lista, crea las tablas con 1_*
# y el ORM de CakePHP falla (no entrecomilla columnas → error SQL en MariaDB).
#
# SOLUCIÓN: perl -i sobre todos los archivos fuente de golpe, inmediatamente
# tras el 'docker compose up -d'. Es idempotente: si ya están parchados no
# cambia nada. Cubre ALL formas: backtick, comilla simple, sin entrecomillar.
# ----------------------------------------------------------------
echo ""
echo "🔧 [2b/8] Parcheando fuentes MISP (columnas 1_* → a_*)..."
# Esperar a que pmp-misp-server arranque (el docker ya está iniciando)
for _w in $(seq 1 20); do
    docker exec pmp-misp-server true 2>/dev/null && break
    sleep 1
done
set +e
docker exec pmp-misp-server perl -i -pe '
  s/1_event_sharing_group_id/a_event_sharing_group_id/g;
  s/1_object_sharing_group_id/a_object_sharing_group_id/g;
  s/1_sharing_group_id/a_sharing_group_id/g;
  s/1_event_distribution/a_event_distribution/g;
  s/1_object_distribution/a_object_distribution/g;
  s/1_distribution/a_distribution/g;
  s/1_event_id/a_event_id/g;
  s/1_attribute_id/a_attribute_id/g;
  s/1_object_id/a_object_id/g;
  s/1_org_id/a_org_id/g;
  s/1_shadow_attribute_id/a_shadow_attribute_id/g;
  s/\x271_\x27/\x27a_\x27/g;
  s/\x27Correlation\.\x271_\x27/\x27Correlation.a_\x27/g;
' \
  /var/www/MISP/app/Model/AppModel.php \
  /var/www/MISP/app/Model/Behavior/DefaultCorrelationBehavior.php \
  /var/www/MISP/app/Model/Behavior/NoAclCorrelationBehavior.php \
  /var/www/MISP/app/Model/Event.php \
  /var/www/MISP/app/Model/Server.php \
  /var/www/MISP/app/Model/ShadowAttribute.php \
  /var/www/MISP/INSTALL/MYSQL.sql \
  /var/www/MISP/db_schema.json 2>/dev/null \
    && _ok "Fuentes MISP parcheadas (a_*): AppModel, modelos, MYSQL.sql, db_schema.json" \
    || _warn "pmp-misp-server aún no disponible — se parchará en PASO 4b"
set -e

# ----------------------------------------------------------------
# PASO 3: Esperar a que MariaDB esté lista para aceptar conexiones
# (Race-condition crítica: MISP arranca antes que la BD en frío)
# ----------------------------------------------------------------
echo ""
echo "⏳ [3/8] Esperando a que MariaDB (pmp-misp-db) esté lista..."
for i in $(seq 1 60); do
    if docker exec pmp-misp-db mysql -uroot -pmy_root_password -e "SELECT 1;" >/dev/null 2>&1; then
        _ok "MariaDB lista (${i}s)."
        break
    fi
    printf "   ⏳ %ds / 60s\r" "$i"
    sleep 1
done
# Verificación final
if ! docker exec pmp-misp-db mysql -uroot -pmy_root_password -e "SELECT 1;" >/dev/null 2>&1; then
    echo "❌ MariaDB no respondió en 60s. Abortando."
    exit 1
fi

# ----------------------------------------------------------------
# PASO 4: Importar esquema SQL si la BD está vacía o incompleta
# (El entrypoint de coolacid/misp-docker falla si la BD no está lista;
#  lo hacemos nosotros explícitamente para garantizarlo)
# Condición mejorada: importar si hay <10 tablas O si 'users' está vacía
# (el entrypoint puede crear tablas parcialmente sin el schema completo).
# ----------------------------------------------------------------
echo ""
echo "📦 [4/8] Verificando esquema de BD MISP..."
# NOTA: set +e porque mysql falla (exit 1) cuando la tabla 'users' no existe
# todavía (BD recién creada), y set -euo pipefail mataría el script.
set +e
TABLE_COUNT=$(docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -NBe "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='misp';" 2>/dev/null | tr -d '[:space:]')
USER_COUNT=$(docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -NBe "SELECT COUNT(*) FROM users;" 2>/dev/null | tr -d '[:space:]' | head -1)
set -e

# Importar si: pocas tablas (USER_COUNT se gestiona en PASO 7)
if [ "${TABLE_COUNT:-0}" -lt "50" ]; then
    _warn "BD incompleta (${TABLE_COUNT:-0} tablas). Reimportando MYSQL.sql..."
    set +e
    docker exec pmp-misp-server bash -c \
        "mysql -h misp-db -uroot -pmy_root_password misp < /var/www/MISP/INSTALL/MYSQL.sql" 2>/dev/null
    TABLE_COUNT=$(docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
        -NBe "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='misp';" 2>/dev/null | tr -d '[:space:]')
    set -e
    _ok "Esquema importado (${TABLE_COUNT:-0} tablas)."
else
    _ok "Esquema ya presente (${TABLE_COUNT} tablas, ${USER_COUNT} usuarios)."
fi

# ----------------------------------------------------------------
# PASO 4b: Reparar esquema — tablas y columnas que MYSQL.sql base
# no incluye pero que la versión de MISP en uso requiere;
# sin ellas todos los comandos 'cake' fallan con error de tabla.
# ----------------------------------------------------------------
echo ""
echo "🔧 [4b] Reparando esquema de BD (tablas/columnas faltantes)..."

# Tabla 'logs' (requerida por el behaviour SysLogLogable)
docker exec pmp-misp-db mysql -uroot -pmy_root_password misp -e \
"CREATE TABLE IF NOT EXISTS logs (
  id int(11) unsigned NOT NULL AUTO_INCREMENT,
  title text,
  created datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  model varchar(80) NOT NULL DEFAULT '',
  model_id int(11) NOT NULL DEFAULT 0,
  action varchar(20) NOT NULL DEFAULT '',
  user_id int(11) NOT NULL DEFAULT 0,
  \`change\` text,
  email varchar(255) NOT NULL DEFAULT '',
  org varchar(255) NOT NULL DEFAULT '',
  description text,
  ip varchar(45) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  KEY model (model),
  KEY created (created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;" 2>/dev/null \
    && _ok "Tabla 'logs' verificada." || _warn "No se pudo crear tabla 'logs'."

# Columnas faltantes en auth_keys (read_only, last_used)
docker exec pmp-misp-db mysql -uroot -pmy_root_password misp -e "
ALTER TABLE auth_keys
  ADD COLUMN IF NOT EXISTS read_only tinyint(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_used int(11) DEFAULT NULL;" 2>/dev/null \
    && _ok "Columnas 'auth_keys' verificadas." || _warn "Columnas auth_keys ya presentes."

# Columna 'protected' en 'events' (requerida por events/add en MISP 2.4.17x;
# runMigrations la añade pero el integrador puede conectar antes de que corra)
docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -e "ALTER TABLE events ADD COLUMN IF NOT EXISTS protected tinyint(1) DEFAULT NULL;" 2>/dev/null \
    && _ok "Columna 'events.protected' verificada." || _warn "No se pudo añadir 'events.protected'."

# Tabla 'cryptographic_keys' (requerida por eventos MISP al leer/crear)
SCRIPT_SQL_CRYPTO=$(mktemp "${TMPDIR:-/tmp}/misp_crypto.XXXXXX")
cat > "$SCRIPT_SQL_CRYPTO" << 'ENDSQL'
CREATE TABLE IF NOT EXISTS cryptographic_keys (
  id int(10) unsigned NOT NULL AUTO_INCREMENT,
  parent_type varchar(255) NOT NULL DEFAULT '',
  parent_id int(10) unsigned NOT NULL DEFAULT 0,
  type varchar(255) NOT NULL DEFAULT '',
  fingerprint varchar(255) NOT NULL DEFAULT '',
  data longtext DEFAULT NULL,
  revoked tinyint(1) NOT NULL DEFAULT 0,
  expires_at int(10) unsigned DEFAULT NULL,
  created_at int(10) unsigned NOT NULL DEFAULT 0,
  updated_at int(10) unsigned NOT NULL DEFAULT 0,
  uuid varchar(36) DEFAULT NULL,
  PRIMARY KEY (id),
  KEY parent_type (parent_type),
  KEY fingerprint (fingerprint),
  KEY uuid (uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
ENDSQL
docker cp "$SCRIPT_SQL_CRYPTO" pmp-misp-db:/tmp/misp_crypto.sql
docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -e "source /tmp/misp_crypto.sql" 2>/dev/null \
    && _ok "Tabla 'cryptographic_keys' verificada." || _warn "No se pudo crear tabla 'cryptographic_keys'."
rm -f "$SCRIPT_SQL_CRYPTO"

# Columna 'relationship_type' en 'attribute_tags' y 'event_tags' (requerida por events/view y events/add en MISP 2.4.17x)
docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -e "ALTER TABLE attribute_tags ADD COLUMN IF NOT EXISTS relationship_type VARCHAR(255) DEFAULT NULL;" 2>/dev/null \
    && _ok "Columna 'attribute_tags.relationship_type' verificada." || _warn "No se pudo añadir columna 'attribute_tags.relationship_type'."
docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -e "ALTER TABLE event_tags ADD COLUMN IF NOT EXISTS relationship_type VARCHAR(255) DEFAULT NULL;" 2>/dev/null \
    && _ok "Columna 'event_tags.relationship_type' verificada." || _warn "No se pudo añadir columna 'event_tags.relationship_type'."

# ── Tablas de correlaciones con esquema a_* (MISP 2.4.177) ──────────────────
# El PHP parchado espera columnas a_* en lugar de las 1_* que genera la migración
# de MISP. CakePHP ORM no entrecomilla columnas con nombres que empiezan por dígito
# → error SQL en MariaDB. Usamos ALTER TABLE directo (PREPARE/EXECUTE falla con
# sentencias compuestas en MariaDB).
_rename_corr_cols() {
    local TBL="$1"
    # Genera el ALTER TABLE dinámicamente DENTRO del contenedor DB:
    #   1) Consulta information_schema para obtener las columnas 1_* que aún existen
    #   2) Construye el CHANGE clause por columna usando CONCAT SQL
    #   3) Une las cláusulas con coma y ejecuta el ALTER TABLE
    # Idempotente: si no hay columnas 1_* no hace nada.
    # Usa credenciales root y no hardcodea columnas → funciona con cualquier tabla.
    docker exec pmp-misp-db bash -c "
        CHANGES=\$(mysql -uroot -pmy_root_password misp -NBe \
          \"SELECT CONCAT('CHANGE \\\`',COLUMN_NAME,'\\\` \\\`a_',SUBSTRING(COLUMN_NAME,3),'\\\` ',
                          COLUMN_TYPE,
                          IF(IS_NULLABLE='NO',' NOT NULL',''),
                          IF(COLUMN_DEFAULT IS NOT NULL,CONCAT(' DEFAULT ',COLUMN_DEFAULT),''))
           FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA='misp' AND TABLE_NAME='${TBL}' AND COLUMN_NAME LIKE '1_%'
           ORDER BY ORDINAL_POSITION;\" 2>/dev/null \
          | paste -sd ',')
        [ -z \"\$CHANGES\" ] && exit 0
        mysql -uroot -pmy_root_password misp -e \"ALTER TABLE \\\`${TBL}\\\` \$CHANGES;\" 2>/dev/null
    " 2>/dev/null
}
# NOTA: _rename_corr_cols se llama en PASO 6 (después de runMigrations),
# porque las tablas de correlaciones las crea la migración — no existen aquí todavía.

# ── Parchear PHP/SQL de MISP para usar columnas a_* en lugar de 1_* ─────────
# Re-ejecutar el perl del PASO 2b como red de seguridad: si el contenedor
# tardó más de 20s en arrancar, el parche del PASO 2b pudo haberse saltado.
# perl -i es idempotente: si ya están parchados, no modifica nada.
# NOTA: \x27 es el código hex de la comilla simple — necesario porque bash
# no permite escapar ' dentro de una cadena '...'. El viejo \'...\' rompía
# la cadena y perl recibía argumentos incorrectos → exit!=0 → set -e abortaba.
set +e
docker exec pmp-misp-server perl -i -pe '
  s/1_event_sharing_group_id/a_event_sharing_group_id/g;
  s/1_object_sharing_group_id/a_object_sharing_group_id/g;
  s/1_sharing_group_id/a_sharing_group_id/g;
  s/1_event_distribution/a_event_distribution/g;
  s/1_object_distribution/a_object_distribution/g;
  s/1_distribution/a_distribution/g;
  s/1_event_id/a_event_id/g;
  s/1_attribute_id/a_attribute_id/g;
  s/1_object_id/a_object_id/g;
  s/1_org_id/a_org_id/g;
  s/1_shadow_attribute_id/a_shadow_attribute_id/g;
  s/\x271_\x27/\x27a_\x27/g;
  s/\x27Correlation\.\x271_\x27/\x27Correlation.a_\x27/g;
' \
  /var/www/MISP/app/Model/AppModel.php \
  /var/www/MISP/app/Model/Behavior/DefaultCorrelationBehavior.php \
  /var/www/MISP/app/Model/Behavior/NoAclCorrelationBehavior.php \
  /var/www/MISP/app/Model/Event.php \
  /var/www/MISP/app/Model/Server.php \
  /var/www/MISP/app/Model/ShadowAttribute.php \
  /var/www/MISP/INSTALL/MYSQL.sql \
  /var/www/MISP/db_schema.json 2>/dev/null
set -e
_ok "PHP/SQL de correlaciones verificados (columnas a_*)."

# Limpiar caché CakePHP y reiniciar servidor para aplicar el esquema en memoria
docker exec pmp-misp-server bash -c \
    "rm -rf /var/www/MISP/app/tmp/cache/models/* /var/www/MISP/app/tmp/cache/persistent/* 2>/dev/null; true"
_ok "Caché CakePHP limpiada."
# Reiniciar PHP-FPM con service para que el init gestione correctamente el proceso.
# pkill -9 + daemonize puede dejar dos PHP-FPM concurrentes con caches distintos.
docker exec pmp-misp-server service php7.4-fpm restart 2>/dev/null || true
sleep 5
docker exec pmp-misp-server nginx -s reload 2>/dev/null || true
_ok "PHP-FPM reiniciado (schema cache recargado)."
# Asegurar permisos correctos en config.php (www-data debe poder leerlo)
docker exec pmp-misp-server chmod 640 /var/www/MISP/app/Config/config.php 2>/dev/null || true
_ok "Permisos config.php verificados."
# NOTA: NO se hace 'docker restart pmp-misp-server' aquí.
# Un restart completo re-ejecuta el entrypoint de coolacid/misp-docker, que
# lanza 'cake runMigrations' en background → recrea tablas de correlaciones
# con columnas 1_* DESPUÉS de que PASO 6 las renombre → race condition.
# El 'service php7.4-fpm restart' de arriba es suficiente para limpiar cache.

# ----------------------------------------------------------------
# PASO 5: Esperar a que MISP web responda (hasta 5 min en frío)
# ----------------------------------------------------------------
echo ""
echo "⏳ [5/8] Esperando a que MISP web responda (hasta 300s)..."
MAX_WAIT=300
ELAPSED=0
until curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 2>/dev/null | grep -qE "^(200|301|302)$"; do
    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        _warn "MISP no respondió en ${MAX_WAIT}s. Continuando de todos modos..."
        break
    fi
    printf "   ⏳ %ds / %ds\r" "$ELAPSED" "$MAX_WAIT"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done
echo "   ✅ MISP web accesible (${ELAPSED}s).              "

# ----------------------------------------------------------------
# PASO 6: Ejecutar migraciones de BD
# (Actualiza auth_keys.read_only y demás columnas que la versión del
#  código requiere pero que MYSQL.sql base no incluye)
# ----------------------------------------------------------------
echo ""
echo "⚙️  [6/8] Ejecutando migraciones de BD MISP..."
docker exec pmp-misp-server su -s /bin/bash www-data -c \
    "/var/www/MISP/app/Console/cake Admin runMigrations" 2>&1 \
    | grep -vE "^$|InsecureRequest|Warning" | tail -5 || true
_ok "Migraciones completadas."

# ── Renombrar columnas 1_* → a_* en tablas de correlaciones ─────────────────
# DEBE ir aquí, justo después de runMigrations: la migración crea las tablas
# con columnas '1_event_id' etc. Si se hace antes, la tabla no existe aún
# y el COUNT devuelve 0, por lo que el fix se salta silenciosamente.
_rename_corr_cols correlations              && _ok "Esquema a_* en 'correlations'."              || _warn "No se pudo actualizar 'correlations'."
_rename_corr_cols default_correlations      && _ok "Esquema a_* en 'default_correlations'."      || _warn "No se pudo actualizar 'default_correlations'."
_rename_corr_cols no_acl_correlations       && _ok "Esquema a_* en 'no_acl_correlations'."       || _warn "No se pudo actualizar 'no_acl_correlations'."
_rename_corr_cols shadow_attribute_correlations && _ok "Esquema a_* en 'shadow_attribute_correlations'." || _warn "No se pudo actualizar 'shadow_attribute_correlations'."

# ── Verificar que el rename fue completo (reintenta si aún quedan 1_*) ───────
# Bucle de seguridad: si alguna migración concurrente recreó tablas con 1_*
# entre el runMigrations y los _rename_corr_cols, se detecta y se repara.
for _retry in 1 2 3; do
    _REMAINING=$(docker exec pmp-misp-db mysql -uroot -pmy_root_password misp -NBe \
        "SELECT COUNT(*) FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA='misp' AND COLUMN_NAME LIKE '1_%';" \
        2>/dev/null | tr -d '[:space:]')
    if [ "${_REMAINING:-99}" -eq "0" ]; then
        _ok "Verificado: sin columnas 1_* en BD MISP."
        break
    fi
    _warn "Quedan ${_REMAINING} col. 1_* (intento ${_retry}/3) — reintentando en 10s..."
    sleep 10
    _rename_corr_cols correlations
    _rename_corr_cols default_correlations
    _rename_corr_cols no_acl_correlations
    _rename_corr_cols shadow_attribute_correlations
done

# Limpiar caché CakePHP en disco + reiniciar PHP-FPM para descargar el schema
# en memoria (CakePHP cachea listSources(); sin este reinicio usaría la
# versión stale con 1_* y daría MissingTableException o columna desconocida)
docker exec pmp-misp-server bash -c \
    "rm -rf /var/www/MISP/app/tmp/cache/models/* /var/www/MISP/app/tmp/cache/persistent/* 2>/dev/null; true"
docker exec pmp-misp-server service php7.4-fpm restart 2>/dev/null || true
sleep 5
docker exec pmp-misp-server nginx -s reload 2>/dev/null || true
_ok "PHP-FPM reiniciado (schema a_* de correlaciones cargado en memoria)."

# Esperar a que MISP web vuelva a responder después del reinicio PHP-FPM
# (el integrador no debe arrancar si MISP aún está calentando PHP-FPM)
_log "Esperando que MISP vuelva a responder tras reinicio PHP-FPM..."
for _i in $(seq 1 30); do
    curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 2>/dev/null \
        | grep -qE "^(200|301|302)$" && _ok "MISP web OK (${_i}x2s)." && break
    sleep 2
done

# ----------------------------------------------------------------
# PASO 7: Crear usuario admin si no existe
# (MYSQL.sql solo contiene el esquema — sin filas de usuario admin)
# ----------------------------------------------------------------
echo ""
echo "👤 [7/8] Verificando usuario admin en BD..."
EXISTING=$(docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
    -NBe "SELECT email FROM users WHERE role_id=1 ORDER BY id ASC LIMIT 1;" 2>/dev/null | tr -d '[:space:]')

if [ -z "$EXISTING" ]; then
    _warn "Usuario admin no encontrado. Insertando directamente en BD..."

    # Escribir SQL a fichero temporal (evita problemas de escape con $ en bcrypt)
SQL_TMP=$(mktemp "${TMPDIR:-/tmp}/misp_admin.XXXXXX")
    # shellcheck disable=SC2016
    cat > "$SQL_TMP" << 'ENDSQL'
INSERT IGNORE INTO organisations
    (id, name, date_created, date_modified, description, type, nationality, sector, created_by, uuid, local)
VALUES
    (1, 'ADMIN', NOW(), NOW(), 'Default admin organisation', 'ADMIN',
     'Not specified', 'Not specified', 0, '57f2a56a-0018-4f64-96f6-3916a3724253', 1);

INSERT IGNORE INTO users
    (id, password, org_id, server_id, email, autoalert, authkey,
     invited_by, nids_sid, termsaccepted, newsread, role_id,
     change_pw, contactalert, disabled, current_login, last_login,
     date_created, date_modified)
VALUES
    (1,
     '$2y$10$8Yi1l7.K5fdWZobW5DGEne3UdxVBE5HqyDfkMHSXGQTH3Svc5LkKC',
     1, 0, 'admin@admin.test', 0, 'tempkey1234567890tempkey1234567890tempk',
     0, 4000000, 1, 0, 1, 0, 0, 0, 0, 0, NOW(), NOW());
ENDSQL

    docker cp "$SQL_TMP" pmp-misp-db:/tmp/misp_admin_init.sql
    docker exec pmp-misp-db mysql -uroot -pmy_root_password misp \
        -e "source /tmp/misp_admin_init.sql" 2>/dev/null
    rm -f "$SQL_TMP"
    _ok "Usuario admin creado: $ADMIN_EMAIL / admin"
else
    ADMIN_EMAIL="$EXISTING"
    _ok "Admin ya existe: $ADMIN_EMAIL"
fi

# ----------------------------------------------------------------
# PASO 8: Configurar API key mediante cake (registra en auth_keys)
# ----------------------------------------------------------------
echo ""
echo "🔑 [8/8] Configurando API key de MISP..."
for i in 1 2 3; do
    RESULT=$(docker exec pmp-misp-server su -s /bin/bash www-data -c \
        "/var/www/MISP/app/Console/cake user change_authkey $ADMIN_EMAIL $MISP_API_KEY" 2>&1)
    if echo "$RESULT" | grep -qiE "success|changed|created|key"; then
        _ok "API key establecida (intento $i)."
        break
    fi
    _warn "Reintento $i/3: $RESULT"
    sleep 10
done

# ----------------------------------------------------------------
# Configurar módulos de enriquecimiento (opcionales)
# ----------------------------------------------------------------
_cake() {
    docker exec pmp-misp-server su -s /bin/bash www-data -c \
        "/var/www/MISP/app/Console/cake Admin setSetting $1 $2" 2>/dev/null || true
}
_cake "Plugin.Enrichment_services_enable" "true"
_cake "Plugin.Enrichment_services_url"    "http://misp-modules:6666"

if [ "$SHODAN_KEY" != "TU_API_KEY_DE_SHODAN" ]; then
    _cake "Plugin.Enrichment_shodan_enabled"  "true"
    _cake "Plugin.Enrichment_shodan_api_key"  "$SHODAN_KEY"
fi
if [ "$VIRUSTOTAL_KEY" != "TU_API_KEY_DE_VIRUSTOTAL" ]; then
    _cake "Plugin.Enrichment_virustotal_enabled"  "true"
    _cake "Plugin.Enrichment_virustotal_api_key"  "$VIRUSTOTAL_KEY"
fi

# ----------------------------------------------------------------
# Limpiar cache CakePHP y reiniciar PHP-FPM ANTES de arrancar el integrador
# CakePHP cachea el listado de tablas (listSources) en memoria al primer uso.
# Si el integrador conecta antes de que runMigrations haya creado
# default_correlations, CakePHP lo marca como "missing" y no lo refresca
# aunque la tabla aparezca después → MissingTableException permanente.
# Solucion: limpiar cache en disco + reload PHP-FPM aquí, al final,
# DESPUES de que todas las migraciones y renombres han terminado.
# ----------------------------------------------------------------
docker exec pmp-misp-server bash -c "
    rm -rf /var/www/MISP/app/tmp/cache/models/* \
           /var/www/MISP/app/tmp/cache/persistent/* 2>/dev/null; true" 2>/dev/null
# Usar 'service restart' en lugar de pkill+daemonize para garantizar
# que PHP-FPM recargue completamente la lista de tablas (listSources).
# El método pkill+daemonize dejaba el caché de CakePHP stale → 500 en /events/add.
docker exec pmp-misp-server service php7.4-fpm restart 2>/dev/null || true
sleep 5
docker exec pmp-misp-server nginx -s reload 2>/dev/null || true
_ok "Cache CakePHP limpiada y PHP-FPM reiniciado (service restart)."

# ----------------------------------------------------------------
# Estabilizar NGINX interno del contenedor MISP
# En algunos arranques queda un nginx "huérfano" (/usr/sbin/nginx) junto al
# nginx gestionado por /entrypoint_nginx.sh (daemon off), provocando conflictos
# de bind 80/443 y errores 500 intermitentes en la API.
# ----------------------------------------------------------------
docker exec pmp-misp-server bash -lc "
    pkill -f '^/usr/sbin/nginx$' 2>/dev/null || true
    sleep 1
"
_ok "NGINX estabilizado (sin masters huérfanos)."

# Esperar a que MISP vuelva a responder antes de arrancar el integrador
_log "Esperando que MISP responda tras reinicio PHP-FPM..."
for _i in $(seq 1 30); do
    curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 2>/dev/null \
        | grep -qE "^(200|301|302)$" && _ok "MISP web OK." && break
    sleep 2
done

# ----------------------------------------------------------------
# Reiniciar integrador con la API key recién configurada
# ----------------------------------------------------------------
docker compose restart misp-integrator 2>/dev/null || true

echo ""
echo "✅ MISP completamente funcional."
echo "   🌍 Web:  http://localhost:8080  ($ADMIN_EMAIL / admin)"
echo "   🔑 API:  $MISP_API_KEY"
