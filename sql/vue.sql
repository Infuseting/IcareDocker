CREATE OR REPLACE VIEW HAS_COURS AS
SELECT
    obg.OBG_ID,
    cla.CLA_ID,
    cla.CLA_Libelle,
    CASE
        WHEN cou.COU_ID IS NOT NULL THEN 'V'
        ELSE 'X'
        END AS Statut
FROM ICA_Obligation_Cours obg
         CROSS JOIN ICA_Classe cla
         LEFT JOIN ICA_Cours cou
                   ON obg.OBG_ID = cou.OBG_ID
                       AND cla.CLA_ID = cou.CLA_ID
WHERE cla.TYPC_ID = obg.TYPC_ID;

CREATE OR REPLACE VIEW ICA_USER_PERMISSION as
SELECT * FROM (
                  SELECT USE_UUID, PER_ID FROM ICA_USER_HAS_ROLE
                                                   JOIN ICA_Role USING(ROL_ID)
                                                   JOIN ICA_ROLE_HAS_PERMISSION USING (ROL_ID)
                  UNION
                  SELECT USE_UUID, PER_ID FROM ICA_USER_HAS_PERMISSION
              ) as USER_PERMISSION;