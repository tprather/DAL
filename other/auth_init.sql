DROP TABLE IF EXISTS auth_users;
CREATE TABLE auth_users (
  UserId                    INT          PRIMARY KEY AUTO_INCREMENT,
  UserName                  VARCHAR(255) UNIQUE  KEY,
  FullName                  VARCHAR(63),
  Email                     VARCHAR(255)
) CHARACTER SET 'utf8' COLLATE 'utf8_general_ci';

DROP TABLE IF EXISTS auth_usergroups;  
CREATE TABLE auth_usergroups (
  UsergroupId               INT          PRIMARY KEY AUTO_INCREMENT,
  UsergroupName             VARCHAR(255) UNIQUE  KEY
) CHARACTER SET 'utf8' COLLATE 'utf8_general_ci' AUTO_INCREMENT=1000000001;
  
DROP TABLE IF EXISTS auth_usergroup_users;
CREATE TABLE auth_usergroup_users (
  UsergroupId               INT,
  UserId                    INT,
  UNIQUE INDEX idx_UsergroupId_UserId (UsergroupId,UserId),
         INDEX idx_UsergroupId        (UsergroupId),
         INDEX idx_UserId             (UserId)
) CHARACTER SET 'utf8' COLLATE 'utf8_general_ci';
  
DROP TABLE IF EXISTS auth_datas;
CREATE TABLE auth_datas (
  DataId                    INT          PRIMARY KEY AUTO_INCREMENT,
  DatagroupId               INT,
  Repository                VARCHAR(255),
  DatabaseName              VARCHAR(63),
  TableName                 VARCHAR(63),
  RowWhereClause            VARCHAR(1023),
  ColumnList                VARCHAR(1023),
  INDEX idx_DatagroupId     (DatagroupId),
  INDEX idx_rdt             (Repository,DatabaseName,TableName),
  INDEX RowWhereClause      (RowWhereClause),
  INDEX ColumnList          (ColumnList)
) CHARACTER SET 'utf8' COLLATE 'utf8_general_ci';
  
DROP TABLE IF EXISTS auth_datagroups;
CREATE TABLE auth_datagroups (
  DatagroupId               INT,
  DatagroupName             VARCHAR(63),
  INDEX        idx_DatagroupId (DatagroupId)
) CHARACTER SET 'utf8' COLLATE 'utf8_general_ci' AUTO_INCREMENT=1000000001;
  
DROP TABLE IF EXISTS auth_dataset_userset;
CREATE TABLE auth_dataset_userset (
  DataSetId                 INT,
  Capability                VARCHAR(15),
  UserSetId                 INT,
  UNIQUE INDEX idx_DataSetId_Capability (DataSetId,Capability,UserSetId),
         INDEX idx_DataSetId            (DataSetId),
         INDEX idx_UserSetId            (UserSetId)
) CHARACTER SET 'utf8' COLLATE 'utf8_general_ci';


INSERT IGNORE INTO auth_usergroups         SET UsergroupName='Test Group 1';
INSERT IGNORE INTO auth_usergroup_users    SET UsergroupId  =1000000001      ,UserId=1;
INSERT IGNORE INTO auth_datagroups         SET DatagroupName='Test Dataset 1';
INSERT IGNORE INTO auth_datas              SET DatagroupId  =1000000001      ,Repository='127.0.0.1/mysql',DatabaseName='kddart_v2_3_2',TableName='project'  ,RowWhereClause=''                          ,ColumnList='ProjectId,ProjectManagerId,TypeId,ProjectName,ProjectStatus,ProjectStartDate,ProjectEndDate,NULL AS ProjectNote';
INSERT IGNORE INTO auth_datas              SET DatagroupId  =0               ,Repository='127.0.0.1/mysql',DatabaseName='kddart_v2_3_2',TableName='site'     ,RowWhereClause=''                          ,ColumnList='SiteId,SiteTypeId,SiteName,SiteAcronym,CurrentSiteManagerId,NULL AS SiteStartDate,NULL AS SiteEndDate';
INSERT IGNORE INTO auth_datas              SET DatagroupId  =0               ,Repository='127.0.0.1/mysql',DatabaseName='kddart_v2_3_2',TableName='trial'    ,RowWhereClause='TrialName NOT LIKE "test%"',ColumnList='*';
INSERT IGNORE INTO auth_datas              SET DatagroupId  =0               ,Repository='127.0.0.1/mysql',DatabaseName='kddart_v2_3_2',TableName='trial'    ,RowWhereClause='TrialName     LIKE "test%"',ColumnList='TrialId,ProjectId,CurrentWorkflowId,TrialTypeId,SiteId,TrialName,TrialNumber,TrialAcronym,DesignTypeId,TrialManagerId,NULL AS TrialStartDate,NULL AS TrialEndDate,TrialNote,OwnGroupId,AccessGroupId,OwnGroupPerm,AccessGroupPerm,OtherPerm';
INSERT IGNORE INTO auth_datas              SET DatagroupId  =0               ,Repository='127.0.0.1/mysql',DatabaseName='kddart_v2_3_2',TableName='trialunit',RowWhereClause=''                          ,ColumnList='*';
INSERT IGNORE INTO auth_dataset_userset    SET DataSetId    =1000000001      ,Capability='READ'           ,UserSetId   =1000000001;
INSERT IGNORE INTO auth_dataset_userset    SET DataSetId    =2               ,Capability='EDIT'           ,UserSetId   =1;
INSERT IGNORE INTO auth_dataset_userset    SET DataSetId    =3               ,Capability='READ'           ,UserSetId   =1;
INSERT IGNORE INTO auth_dataset_userset    SET DataSetId    =4               ,Capability='READ'           ,UserSetId   =1;

GRANT CREATE VIEW ON kddart_v2_3_2.* TO 'kddart_dal'@'localhost';
GRANT DROP        ON kddart_v2_3_2.* TO 'kddart_dal'@'localhost';
