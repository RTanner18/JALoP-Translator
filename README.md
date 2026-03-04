# JALoP Translator Output Module Setup

## Compile the JALoP Module
Retrieve and generate all required header files to compile the Output Module.\
<small>*Note: this process requires many libraries. Install as needed*</small>
### 1) Cloning and building rsyslog repo
```
git clone https://github.com/rsyslog/rsyslog
cd rsyslog
./autogen.sh
make
```

### 2) Configure Makefile
Set SYSLOG_DIR(line 3) of the omjalop Makefile to point to the root of the built rsyslog repo. This points the module to all required header files to build.

### 3) Make the OM and move to the daemon

At the root of the omjalop repo:
```
make
sudo cp omjalop.so /usr/local/lib/rsyslog/
sudo systemctl restart syslog
```
## rsyslogd Setup
### 1) Append the following to /etc/rsyslog.conf
```
module(load="/usr/local/lib/rsyslog/omjalop.so")

template(name="syslog-xml" type="string" string="<entry>\
<timestamp>%TIMESTAMP:::date-rfc3339%</timestamp>\
<hostname>%HOSTNAME%</hostname>\
<appname>%APP-NAME%</appname>\
<procid>%PROCID%</procid>\
<msgid>%MSGID%</msgid>\
<severity>%syslogseverity-text%</severity>\
<facility>%syslogfacility-text%</facility>\
<message>%msg%</message>\
</entry>\n")

action(
    type="omjalop"
    jalop_url="http://localhost:9000"
    jalop_type="log"
    template="syslog-xml"
)
```

### 2) Verify config and restart daemon
Verify: 
```
sudo /usr/local/sbin/rsyslogd -N1
```
Then restart:
```
sudo systemctl restart syslog
systemctl status syslog
```

Verify the daemon is active and running.\
<small>*Note: the logs will show a curl POST failed. That is normal behavior as the JALoP reader is not configured yet.*</small>

## JALoP Reader Config

JALoP Reader is a simple HTTP reciever that stores the files locally. It splits the payload into the metadata and payload files per JALoP2.0.

## Remaining Stuff to Implement

* openssl cert Signature
* Linear chaining for storage


