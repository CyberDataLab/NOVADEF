/* Añade aquí tus constraints/índices; ejemplo compatible Neo4j 5.x:
CREATE CONSTRAINT meta_key IF NOT EXISTS FOR (m:Meta) REQUIRE m.key IS UNIQUE;
CREATE CONSTRAINT actor_id IF NOT EXISTS FOR (a:Actor) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT target_ip IF NOT EXISTS FOR (t:Target) REQUIRE t.ip IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (x:Technique) REQUIRE x.id IS UNIQUE;
CREATE CONSTRAINT evasion_name IF NOT EXISTS FOR (e:Evasion) REQUIRE e.name IS UNIQUE;
CREATE CONSTRAINT kc_name IF NOT EXISTS FOR (k:KillChainPhase) REQUIRE k.name IS UNIQUE;
*/
