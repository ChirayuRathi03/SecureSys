#!/usr/bin/env bash


### DATABASE HARDENING ###
###     1. mysql
###     2. PostgreSQL
###     3. Oracle Database
###     4. Redis

read -sp "Enter MySQL root password (press 'enter' if mysql isnt installed): " MYSQL_ROOT_PASSWORD
echo

if command -v mysql &> /dev/null; then

    # Task 8.1.1.1: Install and configure automated security updates
    sudo dnf install -y dnf-automatic
    sudo sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    sudo systemctl enable --now dnf-automatic.timer

    # Task 8.1.1.2: Remove anonymous users
    mysql -e "DELETE FROM mysql.user WHERE User='';"

    # Task 8.1.1.3: Remove test database
    mysql -e "DROP DATABASE IF EXISTS test;"
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"

    # Task 8.1.1.4: Disable remote root login
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"

    # Task 8.1.1.5: Set a strong root password
    read -s -p "Enter new MySQL root password: " mysql_root_password
    echo
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_root_password';"

    # Task 8.1.1.6: Implement password policies
    mysql -e "INSTALL COMPONENT 'file://component_validate_password';"
    mysql -e "SET GLOBAL validate_password.policy = STRONG;"
    mysql -e "SET GLOBAL validate_password.length = 12;"
    mysql -e "SET GLOBAL default_password_lifetime = 90;"

    # Task 8.1.1.7: Enable binary logging
    echo "log-bin = mysql-bin" | sudo tee -a /etc/my.cnf.d/mysqld.cnf
    echo "binlog_expire_logs_seconds = 604800" | sudo tee -a /etc/my.cnf.d/mysqld.cnf

    # Task 8.1.1.8: Enable SSL/TLS encryption for connections
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/mysql/server-key.pem -out /etc/mysql/server-cert.pem
    echo "ssl-cert=/etc/mysql/server-cert.pem" | sudo tee -a /etc/my.cnf.d/mysqld.cnf
    echo "ssl-key=/etc/mysql/server-key.pem" | sudo tee -a /etc/my.cnf.d/mysqld.cnf

    # Task 8.1.1.9: Set appropriate file permissions
    sudo chown -R mysql:mysql /var/lib/mysql
    sudo chmod 750 /var/lib/mysql
    sudo chmod 640 /etc/my.cnf

    # Task 8.1.1.10: Configure firewall rules
    sudo firewall-cmd --permanent --add-service=mysql
    sudo firewall-cmd --reload

    # Task 8.1.1.11: Enable auditing
    echo "server_audit_events=CONNECT,QUERY,TABLE" | sudo tee -a /etc/my.cnf.d/mysqld.cnf
    echo "server_audit_logging=ON" | sudo tee -a /etc/my.cnf.d/mysqld.cnf

    # Task 8.1.1.12: Disable unnecessary features and plugins
    mysql -e "UNINSTALL PLUGIN daemon_memcached;"

    # Task 8.1.1.13: Implement connection throttling
    echo "max_connections = 100" | sudo tee -a /etc/my.cnf.d/mysqld.cnf
    echo "max_user_connections = 20" | sudo tee -a /etc/my.cnf.d/mysqld.cnf

    # Task 8.1.1.14: Configure automatic backups
    echo "0 2 * * * /usr/bin/mysqldump --all-databases | gzip > /var/backups/mysql_backup_$(date +\%Y\%m\%d).sql.gz" | sudo tee -a /var/spool/cron/root

    # Task 8.1.1.15: Set up database encryption at rest
    echo "early-plugin-load=keyring_file.so" | sudo tee -a /etc/my.cnf.d/mysqld.cnf
    echo "keyring_file_data=/var/lib/mysql-keyring/keyring" | sudo tee -a /etc/my.cnf.d/mysqld.cnf
    sudo mkdir -p /var/lib/mysql-keyring
    sudo chown mysql:mysql /var/lib/mysql-keyring
    sudo chmod 750 /var/lib/mysql-keyring

    sudo systemctl restart mysqld
else
    echo "MySQL is not installed. Skipping MySQL security configuration."
fi
echo "1"

CURRENT_DIR=$(pwd)

store_permissions() {
    ORIGINAL_DIR_PERMS=$(stat -c "%a" "$CURRENT_DIR")
    ORIGINAL_DIR_OWNER=$(stat -c "%U:%G" "$CURRENT_DIR")

    ORIGINAL_PARENT_DIRS=()
    PARENT_DIR="$CURRENT_DIR"
    while [ "$PARENT_DIR" != "/" ]; do
        PARENT_DIR="$(dirname "$PARENT_DIR")"
        if [ "$PARENT_DIR" != "/" ]; then
            ORIGINAL_PARENT_DIRS+=("$PARENT_DIR $(stat -c "%a" "$PARENT_DIR") $(stat -c "%U:%G" "$PARENT_DIR")")
        fi
    done
}

restore_permissions() {
    sudo chown $ORIGINAL_DIR_OWNER "$CURRENT_DIR"
    sudo chmod $ORIGINAL_DIR_PERMS "$CURRENT_DIR"

    for ENTRY in "${ORIGINAL_PARENT_DIRS[@]}"; do
        DIR=$(echo "$ENTRY" | awk '{print $1}')
        PERMS=$(echo "$ENTRY" | awk '{print $2}')
        OWNER=$(echo "$ENTRY" | awk '{print $3}')
        sudo chown $OWNER "$DIR"
        sudo chmod $PERMS "$DIR"
    done
}

if command -v psql &> /dev/null; then
    store_permissions

    GROUP_NAME="postgres_access_group"
    sudo groupadd $GROUP_NAME
    sudo usermod -aG $GROUP_NAME postgres

    sudo chown $USER:$GROUP_NAME "$CURRENT_DIR"
    sudo chmod 770 "$CURRENT_DIR"
    sudo chmod g+s "$CURRENT_DIR"
    
    PARENT_DIR="$(dirname "$CURRENT_DIR")"
    while [ "$PARENT_DIR" != "/" ]; do
        sudo chown $USER:$GROUP_NAME "$PARENT_DIR"
        sudo chmod 770 "$PARENT_DIR"
        sudo chmod g+s "$PARENT_DIR"
        PARENT_DIR="$(dirname "$PARENT_DIR")"
    done
    # Task 8.1.2.1: Use package manager for installation and updates
    sudo dnf update -y postgresql*

    # Task 8.1.2.2: Set a strong superuser password
    read -s -p "Enter new PostgreSQL superuser password: " pg_superuser_password
    echo
    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$pg_superuser_password';"

    # Task 8.1.2.3: Disable remote connections by default
    sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" /var/lib/pgsql/data/postgresql.conf

    # Task 8.1.2.4: Configure client authentication (pg_hba.conf)
    sudo sed -i 's/^host.*all.*all.*ident/host    all    all    127.0.0.1\/32    md5/' /var/lib/pgsql/data/pg_hba.conf
    sudo sed -i 's/^host.*all.*all.*md5/host    all    all    ::1\/128    md5/' /var/lib/pgsql/data/pg_hba.conf

    # Task 8.1.2.5: Enable SSL/TLS for connections
    sudo sed -i "s/#ssl = off/ssl = on/" /var/lib/pgsql/data/postgresql.conf
    if [ ! -f /var/lib/pgsql/data/server.key ]; then
        sudo -u postgres openssl req -new -x509 -days 365 -nodes -text -out /var/lib/pgsql/data/server.crt -keyout /var/lib/pgsql/data/server.key -subj "/CN=localhost"
        sudo chmod 600 /var/lib/pgsql/data/server.key
    fi

    # Task 8.1.2.6: Set appropriate file permissions on data directory
    sudo chmod 700 /var/lib/pgsql/data

    # Task 8.1.2.7: Implement connection rate limiting
    sudo sed -i '/max_connections/d' /var/lib/pgsql/data/postgresql.conf
    echo "max_connections = 100" | sudo tee -a /var/lib/pgsql/data/postgresql.conf

    # Task 8.1.2.8: Enable logging of all database activities
    sudo sed -i "s/#log_statement = 'none'/log_statement = 'all'/" /var/lib/pgsql/data/postgresql.conf
    sudo sed -i "s/#log_min_duration_statement = -1/log_min_duration_statement = 0/" /var/lib/pgsql/data/postgresql.conf

    # Task 8.1.2.9: Configure automated backups
    sudo mkdir -p /var/lib/pgsql/backups
    echo "0 2 * * * /usr/bin/pg_dumpall -U postgres | gzip > /var/lib/pgsql/backups/pg_backup_\$(date +\%Y\%m\%d).sql.gz" | sudo tee /var/spool/cron/postgres

    # Task 8.1.2.10: Implement row-level security
    sudo -u postgres psql << EOF
    DO \$\$
    DECLARE
        row record;
    BEGIN
        FOR row IN SELECT schemaname, tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
        LOOP
            EXECUTE 'ALTER TABLE ' || quote_ident(row.schemaname) || '.' || quote_ident(row.tablename) || ' ENABLE ROW LEVEL SECURITY';
            RAISE NOTICE 'Enabled RLS on %.%', row.schemaname, row.tablename;
        END LOOP;
    END \$\$;
EOF

    # Task 8.1.2.11: Use encrypted passwords in pg_hba.conf
    sudo sed -i 's/md5/scram-sha-256/g' /var/lib/pgsql/data/pg_hba.conf
    sudo sed -i "s/#password_encryption = md5/password_encryption = scram-sha-256/" /var/lib/pgsql/data/postgresql.conf

    # Task 8.1.2.12: Disable superuser login via network
    sudo sed -i '/^host.*postgres/d' /var/lib/pgsql/data/pg_hba.conf
    echo "local   all   postgres                   peer" | sudo tee -a /var/lib/pgsql/data/pg_hba.conf

    # Task 8.1.2.13: Implement least privilege access for roles
    sudo -u postgres psql -c "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;"
    sudo -u postgres psql -c "REVOKE ALL ON SCHEMA public FROM PUBLIC;"

    # Task 8.1.2.14: Enable data encryption at rest
    echo "Data encryption at rest should be configured at the filesystem level."

    # Task 8.1.2.15: Configure firewall rules to restrict access
    if command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --zone=public --add-port=5432/tcp --permanent
        sudo firewall-cmd --reload
    elif command -v ufw &> /dev/null; then
        sudo ufw allow 5432/tcp
    else
        echo "Neither firewall-cmd nor ufw found. Please configure your firewall manually to allow PostgreSQL connections on port 5432."
    fi

    sudo systemctl restart postgresql

    restore_permissions
else
    echo "PostgreSQL is not installed. Skipping PostgreSQL security configuration."
fi

echo "2"

if ! command -v sqlplus &> /dev/null
then
    echo "Oracle Database is not installed. Skipping Oracle-specific tasks."
else
    # Task 8.1.3.1: Install latest security patches automatically
    echo "Applying latest security patches..."
    $ORACLE_HOME/OPatch/opatch auto

    # Task 8.1.3.2: Implement strong password policies
    sqlplus / as sysdba << EOF
    ALTER PROFILE DEFAULT LIMIT
      FAILED_LOGIN_ATTEMPTS 3
      PASSWORD_LIFE_TIME 60
      PASSWORD_REUSE_TIME 365
      PASSWORD_REUSE_MAX 5
      PASSWORD_VERIFY_FUNCTION ora12c_verify_function;
    EXIT;
EOF

    # Task 8.1.3.3: Enable auditing for critical operations
    sqlplus / as sysdba << EOF
    AUDIT ALTER ANY TABLE;
    AUDIT CREATE ANY TABLE;
    AUDIT DROP ANY TABLE;
    AUDIT CREATE USER;
    AUDIT DROP USER;
    AUDIT ALTER DATABASE;
    AUDIT GRANT ANY PRIVILEGE;
    EXIT;
EOF

    # Task 8.1.3.4: Configure network encryption (Oracle Advanced Security)
    echo "SQLNET.ENCRYPTION_SERVER=REQUIRED" >> $ORACLE_HOME/network/admin/sqlnet.ora
    echo "SQLNET.ENCRYPTION_TYPES_SERVER=(AES256,AES192,AES128)" >> $ORACLE_HOME/network/admin/sqlnet.ora

    # Task 8.1.3.5: Implement fine-grained access control
    sqlplus / as sysdba << EOF
    CREATE OR REPLACE FUNCTION emp_policy (
      schema_var IN VARCHAR2,
      table_var IN VARCHAR2
    )
    RETURN VARCHAR2
    IS
    BEGIN
      RETURN 'DEPT = SYS_CONTEXT(''USERENV'', ''DEPARTMENT'')';
    END;
    /

    BEGIN
      DBMS_RLS.ADD_POLICY (
        object_schema => 'HR',
        object_name => 'EMPLOYEES',
        policy_name => 'EMP_POLICY',
        function_schema => 'SYS',
        policy_function => 'EMP_POLICY',
        statement_types => 'SELECT, INSERT, UPDATE, DELETE'
      );
    END;
    /
    EXIT;
EOF

    # Task 8.1.3.6: Enable Transparent Data Encryption (TDE)
    sqlplus / as sysdba << EOF
    ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "keystore_password";
    ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "keystore_password" WITH BACKUP;
    ALTER SYSTEM SET ENCRYPTION KEY IDENTIFIED BY "keystore_password";
    EXIT;
EOF

    # Task 8.1.3.7: Configure Oracle Database Vault
    dvca -action option_configure -owner DBVOWNER -acctmgr DBVACCTMGR

    # Task 8.1.3.8: Implement Virtual Private Database (VPD)
    sqlplus / as sysdba << EOF
    CREATE OR REPLACE FUNCTION auth_orders(
      schema_var IN VARCHAR2,
      table_var IN VARCHAR2
    )
    RETURN VARCHAR2
    IS
      return_val VARCHAR2 (400);
    BEGIN
      return_val := 'SALES_REP_ID = SYS_CONTEXT(''USERENV'', ''SESSION_USER'')';
      RETURN return_val;
    END auth_orders;
    /

    BEGIN
      DBMS_RLS.ADD_POLICY (
        object_schema => 'ORDERS',
        object_name => 'ORDERS_TAB',
        policy_name => 'ORDERS_VPD_POLICY',
        function_schema => 'SYS',
        policy_function => 'AUTH_ORDERS',
        statement_types => 'SELECT, INSERT, UPDATE, DELETE'
      );
    END;
    /
    EXIT;
EOF

    # Task 8.1.3.9: Set appropriate file permissions on Oracle directories
    chmod -R 750 $ORACLE_HOME
    chown -R oracle:oinstall $ORACLE_HOME

    # Task 8.1.3.10: Configure listener security (restrict admin access)
    echo "ADMIN_RESTRICTIONS_LISTENER=ON" >> $ORACLE_HOME/network/admin/listener.ora
    echo "SECURE_CONTROL_LISTENER=TCPS" >> $ORACLE_HOME/network/admin/listener.ora

    # Task 8.1.3.11: Implement connection rate limiting
    echo "CONNECTION_RATE_LISTENER=10" >> $ORACLE_HOME/network/admin/listener.ora

    # Task 8.1.3.12: Enable OS authentication for local connections
    echo "SQLNET.AUTHENTICATION_SERVICES= (BEQ, TCPS, NTS)" >> $ORACLE_HOME/network/admin/sqlnet.ora

    # Task 8.1.3.13: Configure automated RMAN backups
    rman target / << EOF
    CONFIGURE RETENTION POLICY TO RECOVERY WINDOW OF 7 DAYS;
    CONFIGURE BACKUP OPTIMIZATION ON;
    CONFIGURE DEFAULT DEVICE TYPE TO DISK;
    CONFIGURE CONTROLFILE AUTOBACKUP ON;
    CONFIGURE CONTROLFILE AUTOBACKUP FORMAT FOR DEVICE TYPE DISK TO '/backup/autobackup_%F';
    CONFIGURE CHANNEL DEVICE TYPE DISK FORMAT '/backup/%U';
    EXIT;
EOF

    # Task 8.1.3.14: Implement Data Redaction for sensitive information
    sqlplus / as sysdba << EOF
    BEGIN
      DBMS_REDACT.ADD_POLICY(
        object_schema => 'HR',
        object_name => 'EMPLOYEES',
        column_name => 'SALARY',
        policy_name => 'REDACT_SALARY',
        function_type => DBMS_REDACT.FULL,
        expression => '1=1'
      );
    END;
    /
    EXIT;
EOF

    # Task 8.1.3.15: Set up Oracle Label Security
    sqlplus / as sysdba << EOF
    CREATE USER lbacsys IDENTIFIED BY "strong_password";
    GRANT LBAC_DBA TO lbacsys;
    BEGIN
      SA_SYSDBA.CREATE_POLICY (
        policy_name => 'ACCESS_LABELS',
        column_name => 'ACCESS_LABEL'
      );
    END;
    /
    EXIT;
EOF
fi

echo "3"

if ! command -v redis-cli &> /dev/null
then
    echo "Redis is not installed. Skipping Redis-specific tasks."
else
    # Task 8.1.4.1: Disable protected mode if using a trusted environment
    sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf

    # Task 8.1.4.2: Set a strong Redis password
    while true; do
        read -s -p "Enter a strong password for Redis: " REDIS_PASSWORD
        echo
        read -s -p "Confirm the password: " REDIS_PASSWORD_CONFIRM
        echo
        if [ "$REDIS_PASSWORD" = "$REDIS_PASSWORD_CONFIRM" ]; then
            if [ ${#REDIS_PASSWORD} -ge 12 ]; then
                break
            else
                echo "Password is too short. Please use at least 12 characters."
            fi
        else
            echo "Passwords do not match. Please try again."
        fi
    done
    sed -i "s/^# requirepass foobared/requirepass $REDIS_PASSWORD/" /etc/redis/redis.conf

    # Task 8.1.4.3: Rename or disable dangerous commands
    cat << EOF >> /etc/redis/redis.conf
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
EOF

    # Task 8.1.4.4: Enable TLS/SSL encryption
    #cat << EOF >> /etc/redis/redis.conf
#tls-port 6379
#tls-cert-file /path/to/redis.crt
#tls-key-file /path/to/redis.key
#tls-ca-cert-file /path/to/ca.crt
#EOF

    # Task 8.1.4.5: Implement proper network security (firewall rules)
    firewall-cmd --permanent --add-port=6379/tcp
    firewall-cmd --reload

    # Task 8.1.4.6: Set appropriate file permissions on Redis configuration
    chown redis:redis /etc/redis/redis.conf
    chmod 600 /etc/redis/redis.conf

    # Task 8.1.4.7: Configure maxmemory settings to prevent DOS
    echo "maxmemory 2gb" >> /etc/redis/redis.conf
    echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf

    # Task 8.1.4.8: Enable persistent storage (AOF or RDB)
    sed -i 's/^appendonly no/appendonly yes/' /etc/redis/redis.conf

    # Task 8.1.4.9: Implement key event notifications for critical operations
    echo "notify-keyspace-events KEA" >> /etc/redis/redis.conf

    # Task 8.1.4.10: Configure automatic failover in a cluster setup
    # Note: This is a simplified example. Actual cluster setup requires more configuration.
    #echo "cluster-enabled yes" >> /etc/redis/redis.conf
    #echo "cluster-config-file nodes.conf" >> /etc/redis/redis.conf
    #echo "cluster-node-timeout 5000" >> /etc/redis/redis.conf

    # Task 8.1.4.11: Set up ACL for fine-grained access control
    cat << EOF >> /etc/redis/redis.conf
user default on >$REDIS_PASSWORD ~* &* +@all
user readonly on >readonly ~* &* +@read
EOF

    # Task 8.1.4.12: Implement connection rate limiting
    #echo "maxclients-per-throttle-period 1000" >> /etc/redis/redis.conf
    #echo "throttle-period 60" >> /etc/redis/redis.conf

    # Task 8.1.4.13: Configure automated backups
    cat << EOF > /etc/cron.daily/redis-backup
#!/bin/bash
BACKUP_DIR="/var/lib/redis/backups"
DATETIME=\$(date '+%Y%m%d_%H%M%S')
mkdir -p \$BACKUP_DIR
redis-cli -a $REDIS_PASSWORD SAVE
cp /var/lib/redis/dump.rdb \$BACKUP_DIR/redis_backup_\$DATETIME.rdb
find \$BACKUP_DIR -type f -mtime +7 -delete
EOF
    chmod +x /etc/cron.daily/redis-backup

    # Task 8.1.4.14: Set appropriate maxclients value
    echo "maxclients 10000" >> /etc/redis/redis.conf

    # Task 8.1.4.15: Enable lazy freeing of objects
    cat << EOF >> /etc/redis/redis.conf
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes
EOF

    echo "Restarting Redis to apply changes..."
    systemctl restart redis

    echo "Redis security tasks completed."
fi

echo "4"

### WEB SERVER HARDENING ###


if rpm -q httpd &>/dev/null; then
    # Task 8.2.1.1: Disable directory listing
    sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/Options Indexes/Options -Indexes/' /etc/httpd/conf/httpd.conf

    # Task 8.2.1.2: Remove server signature
    echo "ServerSignature Off" >> /etc/httpd/conf/httpd.conf

    # Task 8.2.1.3: Remove server tokens (Hide Apache version)
    echo "ServerTokens Prod" >> /etc/httpd/conf/httpd.conf

    # Task 8.2.1.4: Disable unnecessary modules (Example: mod_status)
    sed -i '/LoadModule status_module modules\/mod_status.so/s/^/#/' /etc/httpd/conf.modules.d/00-base.conf

    # Task 8.2.1.5: Use TLS/SSL encryption (Ensure all communication is encrypted)
    yum install mod_ssl -y --nogpgcheck
    sed -i '/SSLCipherSuite/ s/.*/SSLCipherSuite HIGH:!aNULL:!MD5/' /etc/httpd/conf.d/ssl.conf

    # Task 8.2.1.6: Enable firewall (Only allow HTTP/HTTPS ports)
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload

    # Task 8.2.1.7: Restrict file permissions (/var/www)
    chown -R apache:apache /var/www
    chmod -R 755 /var/www

    # Task 8.2.1.8: Use ModSecurity (Add Web Application Firewall)
    yum install mod_security -y --nogpgcheck
    systemctl restart httpd

    # Task 8.2.1.9: Log rotation (Rotate logs regularly)
    cat <<EOF >/etc/logrotate.d/httpd
/var/log/httpd/*log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /bin/systemctl reload httpd.service > /dev/null 2>/dev/null || true
    endscript
}
EOF

    # Task 8.2.1.10: Use SELinux (Ensure SELinux is enforcing)
    echo "# Task 8.2.1.10: Use SELinux (Ensure SELinux is enforcing)"
    if sestatus | grep -q 'Current mode: enforcing'; then
        echo "SELinux is in enforcing mode."
    else
        setenforce 1
    fi

    # Task 8.2.1.11: Restrict CGI execution
    sed -i '/Options/s/ExecCGI/-ExecCGI/' /etc/httpd/conf/httpd.conf

    # Task 8.2.1.12: Implement timeout limits (DoS attack prevention)
    sed -i 's/^Timeout .*/Timeout 60/' /etc/httpd/conf/httpd.conf

    # Task 8.2.1.13: Enable HSTS (Strict Transport Security)
    echo 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' >> /etc/httpd/conf.d/ssl.conf

    # Task 8.2.1.14: Disable unused protocols (Disable HTTP/1.0 if HTTP/1.1 is required)
    echo 'Protocols h2 http/1.1' >> /etc/httpd/conf/httpd.conf

    # Task 8.2.1.15: Limit request size (Prevent large request attacks)
    echo "LimitRequestBody 1024000" >> /etc/httpd/conf/httpd.conf

    # Restart Apache service to apply changes
    systemctl restart httpd
else
    echo "Apache HTTP Server (httpd) is not installed. Skipping Apache hardening."
fi

echo "1"

nginx_check=$(rpm -q nginx)
if [[ $nginx_check == *"is not installed"* ]]; then
    echo "Nginx is not installed. Skipping Nginx hardening tasks."
else
    echo "Nginx is installed. Proceeding with hardening tasks."

    # Task 8.2.2.1: Disable directory listing
    sed -i '/autoindex /c\    autoindex off;' /etc/nginx/nginx.conf

    # Task 8.2.2.2: Remove server signature
    sed -i '/server_tokens /c\    server_tokens off;' /etc/nginx/nginx.conf

    # Task 8.2.2.3: Use TLS/SSL and disable weak ciphers
    sed -i '/ssl_protocols/c\    ssl_protocols TLSv1.2 TLSv1.3;' /etc/nginx/nginx.conf

    # Task 8.2.2.4: Restrict file permissions
    chown -R nginx:nginx /etc/nginx/
    chmod -R 750 /etc/nginx/

    # Task 8.2.2.5: Limit request size
    sed -i '/client_max_body_size/c\    client_max_body_size 1M;' /etc/nginx/nginx.conf

    # Task 8.2.2.6: Restrict IP access
    server_block=$(grep -n "server {" /etc/nginx/nginx.conf)

    if [ -z "$server_block" ]; then
        echo "No server block found. Please ensure a server block exists."
    else
        server_line=$(echo "$server_block" | head -n 1 | cut -d: -f1)
        
        sed -i "${server_line}a \    location /admin/ { allow 192.168.1.0/24; deny all; }" /etc/nginx/nginx.conf
    fi

    # Task 8.2.2.7: Use SELinux
    setenforce 1

    # Task 8.2.2.8: Ensure latest version of nginx is installed
    dnf update nginx -y --nogpgcheck

    systemctl reload nginx
fi

echo '2'

if systemctl list-units --type=service | grep -q 'tomcat'; then
    echo "Tomcat is installed. Proceeding with hardening steps."
    
    # Task 8.2.3.1: Remove unnecessary apps
    if [ -d /usr/share/tomcat/webapps/examples ]; then
        rm -rf /usr/share/tomcat/webapps/examples
    fi

    # Task 8.2.3.2: Disable directory listing
    web_xml="/usr/share/tomcat/conf/web.xml"
    if grep -q 'listings="true"' "$web_xml"; then
        sed -i 's/listings="true"/listings="false"/' "$web_xml"
    fi

    # Task 8.2.3.3: Use strong ciphers for HTTPS
    server_xml="/usr/share/tomcat/conf/server.xml"
    if grep -q 'protocol="org.apache.coyote.http11.Http11NioProtocol"' "$server_xml"; then
        sed -i '/protocol="org.apache.coyote.http11.Http11NioProtocol"/a \        ciphers="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"' "$server_xml"
    fi

    # Task 8.2.3.4: Remove server version information
    sed -i 's/server="Apache-Coyote"/server="false"/' "$server_xml"

    # Task 8.2.3.5: Disable Manager/HostManager
    if [ -d /usr/share/tomcat/webapps/manager ]; then
        rm -rf /usr/share/tomcat/webapps/manager
    fi
    if [ -d /usr/share/tomcat/webapps/host-manager ]; then
        rm -rf /usr/share/tomcat/webapps/host-manager
    fi

    # Task 8.2.3.6: Use SELinux
    if getenforce | grep -q 'Disabled'; then
        setenforce 1
    fi

    # Task 8.2.3.7: Limit permissions
    chown -R tomcat:tomcat /usr/share/tomcat
    chmod -R 750 /usr/share/tomcat

    # Task 8.2.3.8: Log rotation
    if [ ! -f /etc/logrotate.d/tomcat ]; then
        cat <<EOF > /etc/logrotate.d/tomcat
/usr/share/tomcat/logs/*.log {
    daily
    rotate 14
    compress
    missingok
    create 0640 tomcat tomcat
    notifempty
    sharedscripts
    postrotate
        /bin/systemctl reload tomcat > /dev/null 2>/dev/null || true
    endscript
}
EOF
    fi

    # Task 8.2.3.9: Disable HTTP methods
    if grep -q '<Connector' "$server_xml"; then
        sed -i '/<Connector/i \    <Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.\d+\.\d+\.\d+|::1" denyStatus="403" />' "$server_xml"
    fi

    # Task 8.2.3.11: Session management
    context_xml="/usr/share/tomcat/conf/context.xml"
    if grep -q '<Context' "$context_xml"; then
        sed -i '/<Context/i \    <SessionCookie secure="true" httpOnly="true" />' "$context_xml"
    fi

    # Task 8.2.3.12: Set appropriate timeouts
    if grep -q '<Connector' "$server_xml"; then
        sed -i '/<Connector/a \        connectionTimeout="20000"' "$server_xml"
    fi

    # Task 8.2.3.13: Disable AJP connector
    if grep -q 'protocol="AJP/1.3"' "$server_xml"; then
        sed -i '/protocol="AJP\/1.3"/d' "$server_xml"
    fi

    # Task 8.2.3.14: Regularly update Tomcat
    yum update -y tomcat

    # Task 8.2.3.15: Limit request size
    if grep -q '<Connector' "$server_xml"; then
        sed -i '/<Connector/a \        maxPostSize="1048576"' "$server_xml"
    fi
    
    # Reload Tomcat to apply changes
    systemctl reload tomcat
else
    echo "Tomcat is not installed. Skipping Tomcat hardening steps."
fi

echo '3'

echo "Checking if Lighttpd is installed..."
if systemctl list-units --type=service | grep -q 'lighttpd'; then
    
    lighttpd_conf="/etc/lighttpd/lighttpd.conf"
    
    # Task 8.2.4.1: Disable directory listing
    if grep -q 'dir-listing.activate' "$lighttpd_conf"; then
        sed -i 's/dir-listing.activate.*/dir-listing.activate = "disable"/' "$lighttpd_conf"
    else
        echo 'dir-listing.activate = "disable"' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.2: Use strong SSL/TLS ciphers
    if grep -q 'ssl.cipher-list' "$lighttpd_conf"; then
        sed -i 's/ssl.cipher-list.*/ssl.cipher-list = "HIGH:!aNULL:!MD5"/' "$lighttpd_conf"
    else
        echo 'ssl.cipher-list = "HIGH:!aNULL:!MD5"' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.3: Remove version information
    if grep -q 'server.tag' "$lighttpd_conf"; then
        sed -i 's/server.tag.*/server.tag = ""/' "$lighttpd_conf"
    else
        echo 'server.tag = ""' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.4: Limit request size
    if grep -q 'server.max-request-size' "$lighttpd_conf"; then
        sed -i 's/server.max-request-size.*/server.max-request-size = 1048576/' "$lighttpd_conf"
    else
        echo 'server.max-request-size = 1048576' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.5: Restrict file permissions
    chown -R lighttpd:lighttpd /var/www/html
    chmod -R 750 /var/www/html

    # Task 8.2.4.6: Enable SELinux
    if getenforce | grep -q 'Disabled'; then
        setenforce 1
    fi

    # Task 8.2.4.7: Disable unnecessary modules
    unnecessary_modules=("mod_userdir" "mod_status" "mod_auth" "mod_webdav")
    for module in "${unnecessary_modules[@]}"; do
        if grep -q "$module" "$lighttpd_conf"; then
            sed -i "/$module/d" "$lighttpd_conf"
        fi
    done

    # Task 8.2.4.8: Use timeouts
    if grep -q 'server.max-keep-alive-idle' "$lighttpd_conf"; then
        sed -i 's/server.max-keep-alive-idle.*/server.max-keep-alive-idle = 5/' "$lighttpd_conf"
    else
        echo 'server.max-keep-alive-idle = 5' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.9: Regular log review
    if [ ! -f /etc/logrotate.d/lighttpd ]; then
        cat <<EOF > /etc/logrotate.d/lighttpd
/var/log/lighttpd/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 0640 lighttpd lighttpd
    postrotate
        /bin/systemctl reload lighttpd > /dev/null 2>/dev/null || true
    endscript
}
EOF
    fi

    # Task 8.2.4.10: Disable unused HTTP methods
    if grep -q 'url.rewrite-once' "$lighttpd_conf"; then
        sed -i '/url.rewrite-once/a \    "^(TRACE|OPTIONS)" => "403"' "$lighttpd_conf"
    else
        echo 'url.rewrite-once = ( "^(TRACE|OPTIONS)" => "403" )' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.11: Implement rate limiting
    lighttpd_conf="/etc/lighttpd/lighttpd.conf"

    if grep -q 'server.modules' "$lighttpd_conf"; then
        if lighttpd -V | grep -q 'mod_evasive'; then
            if ! grep -q '"mod_evasive"' "$lighttpd_conf"; then
                sed -i '/server.modules/a \    "mod_evasive"' "$lighttpd_conf"
            fi
            
            # Create the evasive configuration
            cat <<EOF > /etc/lighttpd/conf-available/90-evasive.conf
evasive.max-conns-per-ip = 10
evasive.silent = "disable"
EOF
            
            # Enable the evasive module
            lighttpd-enable-mod evasive            
        else
            echo "mod_evasive not supported or not installed on this version of Lighttpd."
        fi
    fi

    # Task 8.2.4.12: Disable IPv6
    if grep -q 'server.use-ipv6' "$lighttpd_conf"; then
        sed -i 's/server.use-ipv6.*/server.use-ipv6 = "disable"/' "$lighttpd_conf"
    else
        echo 'server.use-ipv6 = "disable"' >> "$lighttpd_conf"
    fi

    # Task 8.2.4.13: Secure temp files
    chown root:root /tmp
    chmod 1777 /tmp

    # Task 8.2.4.14: Patch regularly
    yum update -y lighttpd
    
    systemctl reload lighttpd

else
    echo "Lighttpd is not installed. Skipping Lighttpd hardening steps."
fi

echo '4'

# Task 8.3.1: Rootkit detection
dnf install -y rkhunter --nogpgcheck
rkhunter --update
rkhunter --checkall --sk --quiet
echo "0 3 * * * /usr/bin/rkhunter --checkall --sk --quiet" >> /etc/crontab
read -p "Enter email address for rootkit scan alerts (leave empty to skip): " email
if [[ -n $email ]]; then
  echo "MAILTO=\"$email\"" >> /etc/crontab
  echo "Adding email notification for rootkit detection..."
  echo "0 5 * * * /bin/grep 'Warning' /var/log/rkhunter.log | mail -s 'Rootkit Scan Warnings' $email" >> /etc/crontab
else
  echo "Skipping email alerts configuration."
fi

rkhunter --propupd

echo 'done'

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################