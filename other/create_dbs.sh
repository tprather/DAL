#!/bin/bash

# Copyright (c) 2012, Diversity Arrays Technology, All rights reserved.

# Author    : Puthick Hok
# Created   : 18/01/2012
# Modified  :
# Purpose   : This script will take SQL dump files and recreate
#             the databases according to the dump file. Please read through
#             the script to see exactly what it does.

# database access configuration (user will be prompted for MySQL password during the run of the script)
MYSQL_UNAME='root'
PG_UNAME='postgres'
MONETDB_UNAME='monetdb'
DB_UNAME='kddart_dal'
DB_HOST='localhost'
# set your own postgres password as configured on your server
DB_PASS='yourSecurePassword'

handle_mysql() {

    UNAME=$1
    PASS=$2
    DB=$3
    SQL_FILE=$4
    DB_UNAME=$5
    DB_HOST=$6
    
    echo "MySQL DB: $DB"

    DB_EXIST=`mysql -u $UNAME --password=$PASS -e 'show databases;' | gawk '{print $1}' | grep "^$DB\$"`

    echo "MySQL DB Status: $DB_EXIST"

    if [ ${#DB_EXIST} -gt 0 ]
    then
	      echo "Drop $DB"
	      mysql -u $UNAME --password=$PASS -e "drop database $DB;"
    fi

    mysql -u $UNAME --password=$PASS -e "CREATE DATABASE \`$DB\`;"

    #QUOTED_DB_UNAME="'"$DB_UNAME"'"

    #echo "Quoted Db Uname: $QUOTED_DB_UNAME"
    echo "DB: $DB | Username: $DB_UNAME | Host: $DB_HOST"

    mysql $DB -u $UNAME --password=$PASS < $SQL_FILE

    mysql -u $UNAME --password=$PASS -e "grant SELECT, INSERT, UPDATE, DELETE, CREATE ON $DB.* TO '$DB_UNAME'@'$DB_HOST';"

}

handle_monetdb() {

    UNAME=$1
    PASS=$2
    DB=$3
    SQL_FILE=$4
    DB_UNAME=$5
    DB_PASS=$6

    export DOTMONETDBFILE="./.monetdbuser"
    cat > ${DOTMONETDBFILE} << EOF
user=$UNAME
password=$PASS
language=sql
EOF

    DB_EXIST_STATUS=`monetdb status $DB | grep "$DB"`

    if [ ${#DB_EXIST_STATUS} -gt 0 ]
    then

        monetdb stop $DB
        monetdb destroy $DB
    fi

    monetdb create $DB

    monetdb release $DB

    #echo "CREATE USER \"$DB_UNAME\" WITH PASSWORD '"$DB_PASS"' NAME 'DAL db user' SCHEMA \"sys\";" | mclient -d $DB

    #echo "CREATE ROLE \"daladmin\" WITH ADMIN CURRENT_USER;" | mclient -d $DB

    #echo "GRANT \"daladmin\" TO \"$DB_UNAME\" WITH ADMIN OPTION;" | mclient -d $DB

    #echo "CREATE SCHEMA \"$DB\" AUTHORIZATION \"$DB_UNAME\";" | mclient -d $DB

    #echo "ALTER USER \"$DB_UNAME\" SET SCHEMA \"$DB\";" | mclient -d $DB

    #rm ${DOTMONETDBFILE} 

    #export DOTMONETDBFILE="./.monetdbuser"
    #cat > ${DOTMONETDBFILE} << EOF
#user=$DB_UNAME
#password=$DB_PASS
#language=sql
#EOF

    mclient -d $DB < $SQL_FILE

    rm ${DOTMONETDBFILE} 
}

if [ $# -lt 6 ]
then
    echo -e "Usage: $0 <postgres dbname> <postgres sql> <main module dbname> <main module mysql sql> <marker dbname> <marker mysql sql> [1 (force drop db if exists)]"
    exit 1
fi

PG_DBNAME=$1
PG_SQL=$2
MAIN_DBNAME=$3
MAIN_SQL=$4
MARKER_DBNAME=$5
MARKER_SQL=$6

FORCE_DROP_DB=0

if [[ ! -z "$7" ]]
then
    if [ $7 -eq 1 ]
    then
        FORCE_DROP_DB=1
    fi
fi

stty -echo

echo -n "Password for $MYSQL_UNAME in MySQL: "
read MYSQL_PASS

stty echo

echo

echo -n "Password for $MONETDB_UNAME in MonetDB: "

stty -echo

read MDB_PASS

stty echo

echo

POSTGRES_DB_EXIST=`psql -h $DB_HOST -l -U $PG_UNAME | gawk '{print $1}' | grep "^$PG_DBNAME\$"`

if [ ${#POSTGRES_DB_EXIST} -gt 0 ]
then
    if [ $FORCE_DROP_DB -eq 0 ]
    then
        echo "$PG_DBNAME already exist."
        exit 1
    fi
fi

MAIN_DB_EXIST=`mysql -u $MYSQL_UNAME --password=$MYSQL_PASS -e 'show databases;' | gawk '{print $1}' | grep "^$MAIN_DBNAME\$"`

#echo "Main MySQL DB Status: $MAIN_DB_EXIST"

if [ ${#MAIN_DB_EXIST} -gt 0 ]
then
	  if [ $FORCE_DROP_DB -eq 0 ]
    then
        echo "$MAIN_DBNAME already exist."
        exit 1
    fi
fi

#echo "MARKER_DBNAME: $MARKER_DBNAME"

MARKER_DB_EXIST=`monetdb status $MARKER_DBNAME | grep "$MARKER_DBNAME"`

#echo "Marker MySQL DB Status: $MARKER_DB_EXIST"

if [ ${#MARKER_DB_EXIST} -gt 0 ]
then
	  if [ $FORCE_DROP_DB -eq 0 ]
    then
        echo "$MARKER_DBNAME already exist."
        exit 1
    fi
fi

echo "Finish checking"

# Finish checking and start doing

if [ ${#POSTGRES_DB_EXIST} -gt 0 ]
then
    echo "Drop $PG_DBNAME"
    dropdb -h $DB_HOST -U $PG_UNAME  $PG_DBNAME
fi

echo "Create $PG_DBNAME"
createdb -h $DB_HOST $PG_DBNAME -U $PG_UNAME

DB_USER_EXIST=`psql -h $DB_HOST -U $PG_UNAME -d $PG_DBNAME -c "\du" | gawk '{print $1}' | grep "^$DB_UNAME\$"`

if [ ${#DB_USER_EXIST} -gt 0 ]
then
    echo "Delete user $DB_UNAME"
    psql -h $DB_HOST -U $PG_UNAME -c "reassign owned by $DB_UNAME to $PG_UNAME"
    psql -h $DB_HOST -U $PG_UNAME -c "revoke all on database $PG_DBNAME from $DB_UNAME"
    psql -h $DB_HOST -U $PG_UNAME -c "drop user $DB_UNAME"
fi

QUOTED_DB_PASS="'"$DB_PASS"'"

echo "Create user $DB_NAME"
psql -h $DB_HOST -U $PG_UNAME -c "create user $DB_UNAME createdb password $QUOTED_DB_PASS"

psql -h $DB_HOST -U $PG_UNAME -d $PG_DBNAME -f $PG_SQL

for tbl in `psql -h $DB_HOST -U $PG_UNAME -qAt -c "select tablename from pg_tables where schemaname = 'public';" ${PG_DBNAME}` `psql -h $DB_HOST -U $PG_UNAME -qAt -c "select sequence_name from information_schema.sequences where sequence_schema = 'public';" ${PG_DBNAME}` `psql -h $DB_HOST -U $PG_UNAME -qAt -c "select table_name from information_schema.views where table_schema = 'public';" ${PG_DBNAME}` ;
do
	psql -h $DB_HOST -U $PG_UNAME -c "alter table \"$tbl\" owner to $DB_UNAME" -d $PG_DBNAME;
done

QUOTED_DB_UNAME="'"$DB_UNAME"'"

MYSQL_DB_EXIST=`mysql -u $MYSQL_UNAME --password=$MYSQL_PASS -e "select User from mysql.user where User = $QUOTED_DB_UNAME;"`

if [ ${#MYSQL_DB_EXIST} -gt 0 ]
then
    echo "Drop $DB_UNAME from MySQL"
    mysql -u $MYSQL_UNAME --password=$MYSQL_PASS -e "drop user '$DB_UNAME'@'$DB_HOST';"
fi

echo "Create $DB_UNAME in MySQL"
mysql -u $MYSQL_UNAME --password=$MYSQL_PASS -e "grant usage on *.* to '$DB_UNAME'@'$DB_HOST' IDENTIFIED BY '$DB_PASS';"

handle_mysql $MYSQL_UNAME $MYSQL_PASS $MAIN_DBNAME $MAIN_SQL $DB_UNAME $DB_HOST
handle_monetdb $MONETDB_UNAME $MDB_PASS $MARKER_DBNAME $MARKER_SQL $DB_UNAME $DB_PASS

echo "Completed successfully!"
