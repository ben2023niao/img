#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi
#script_dir_path=$(dirname $(readlink -f $0)) #绝对路径技巧

server_name=${1:-img.18x18b.com}  #默认域名写法
echo "[自动化部署配置] ==> $server_name" 

check_yum=`whereis yum | sed "s/yum://g" | md5sum | awk '{print $1}'`
check_apt=`whereis apt | sed "s/apt://g" | md5sum | awk '{print $1}'`

if [[ "$check_yum" != '68b329da9893e34099c7d8ad5cb9c940' ]];then install=yum ;fi
if [[ "$check_apt" != '68b329da9893e34099c7d8ad5cb9c940' ]];then install=apt ;fi
echo "[服务器包管理器] ==> $install" 
echo " "

function init_ulimits(){         #[ulimits 配置]
cat > /etc/security/limits.conf <<EOF
* soft noproc 20480
* hard noproc 20480
root soft nofile 65535
root hard nofile 65535
* soft nofile 65535
* hard nofile 65535
EOF
ulimit -n 65535
ulimit -u 20480
echo "[ulimits 配置] ==> OK" 
}

function init_tomcat() {         #[tomcat 用户ssh密钥配置]
useradd tomcat
usermod -aG sudo tomcat
mkdir -p /home/tomcat/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxV6WVONrWBPUNIhw4IrtZSF8F7gUrRlXgZ0CXeAQIFSFXve8qAQ86lIWWDSKjygGfl6FKUoxYzhRzxfhRiKjAwi3BH7d1lKlFwzOBvOPeS57K5znWXPz+E09/Vj1xJ9MHqzl3/Ece0M/2srPtVTgB1Ico8AFi9pPaYZSy3bue36OKVFnC9kVvkriiIe/k/vux5KF/TcXCkc91IVMGCqp8H8NqaJnQWmFB1RYMz9JUe6G9V400iTn9cJmcfS7r5jfT+ZI3K0s6FiCDvQ5LsRNcZhD4uy6YdkG3QBOPOuSwR1sHOcfADyMkWPAXezasI7nfAj7VuuMiqvVt2Ju5A1low== tomcat@jump' > /home/tomcat/.ssh/authorized_keys
chown -R tomcat.tomcat /home/tomcat/
echo "[tomcat 用户ssh密钥配置] ==> OK"
}

function init_history(){         #[history 优化]
if ! grep "HISTTIMEFORMAT" /etc/profile >/dev/null 2>&1
then 
cat > /etc/profile <<EOF
if [ "$(id -u)" -eq 0 ]; then
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
else
  PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
fi
export PATH
if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then
    else
      PS1='$ '
    fi
  fi
fi
if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi
                UserIP=$(who -u am i | cut -d"(" -f 2 | sed -e "s/[()]//g")
                export HISTTIMEFORMAT="[%F %T] [`whoami`] [${UserIP}] "
EOF
fi
echo "[history 优化] ==> OK"
}

function init_ssh(){             #[SSH 优化]
[ -f /etc/ssh/sshd_config ] && sed -ir '13 iUseDNS no\nGSSAPIAuthentication no' /etc/ssh/sshd_config && /etc/init.d/sshd restart >/dev/null 2>&1
echo "[SSH 优化] ==> OK"
}

function init_kernel(){          #[内核 优化]
cat > /etc/sysctl.conf <<EOF
fs.file-max = 65535

net.ipv4.tcp_max_tw_buckets = 5000            
#表示系统同时保持TIME_WAIT套接字的最大数量，如果超过这个数字，TIME_WAIT套接字将立刻被清除并打印警告信息。减少它的最大数量，避免Squid服务器被大量的TIME_WAIT套接字拖死。

net.ipv4.tcp_max_orphans = 3276800            
#系统中最多有多少个TCP套接字不被关联到任何一个用户文件句柄上。

net.ipv4.tcp_fin_timeout = 30                 
#表示如果套接字由本端要求关闭，这个参数决定了它保持在FIN-WAIT-2状态的时间。

net.ipv4.tcp_keepalive_time = 1200            
#表示当keepalive起用的时候，TCP发送keepalive消息的频度。缺省是2小时，改为20分钟。

net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_syncookies = 1

net.ipv4.tcp_tw_reuse = 1                      
#表示开启重用，允许将TIME-WAIT sockets重新用于新的TCP连接。

net.ipv4.tcp_timestamps = 0                    
#时间戳可以避免序列号的卷绕。一个1Gbps的链路肯定会遇到以前用过的序列号，时间戳能够让内核接受这种“异常”的数据包，这里需要将其关掉。

net.ipv4.tcp_tw_recycle = 1                    
#表示开启TCP连接中TIME-WAIT sockets的快速回收。

net.ipv4.ip_local_port_range = 1024 65000      
#表示用于向外连接的端口范围。缺省情况下很小：32768到61000，改为1024到65000。

net.ipv4.tcp_mem = 786432 1048576 1572864      
#同样有3个值
#net.ipv4.tcp_mem[0]:低于此值，TCP没有内存压力
#net.ipv4.tcp_mem[1]:在此值下，进入内存压力阶段
#net.ipv4.tcp_mem[2]:高于此值，TCP拒绝分配socket。
#可根据物理内存大小进行调整，如果内存足够大的话，可适当往上调。建议94500000 915000000 927000000。

net.core.wmem_default = 8388608                
#发送套接字缓冲区大小的缺省值（以字节为单位）

net.core.rmem_default = 8388608                
#接收套接字缓冲区大小的缺省值（以字节为单位）

net.core.rmem_max = 16777216                   
#接收套接字缓冲区大小的最大值（以字节为单位）

net.core.wmem_max = 16777216                   
#发送套接字缓冲区大小的最大值（以字节为单位）

net.ipv4.tcp_wmem = 8192 436600 873200         
#TCP写buffer,可参考的优化值: 8192 436600 873200

net.ipv4.tcp_rmem = 32768 436600 873200        
#TCP读buffer,可参考的优化值: 32768 436600 873200

net.core.somaxconn = 65408                    
#web应用中listen函数的backlog默认会给我们内核参数的net.core.somaxconn限制到128，而nginx定义的NGX_LISTEN_BACKLOG默认为511，所以有必要调整这个值。

net.core.netdev_max_backlog = 262144           
#每个网络接口接收数据包的速率比内核处理这些包的速率快时，允许送到队列的数据包的最大数目。

net.ipv4.tcp_max_syn_backlog = 8192            
#表示SYN队列的长度，默认为1024，加大队列长度为8192，可以容纳更多等待连接的网络连接数。

net.ipv4.tcp_retries2 = 5
net.ipv4.conf.lo.arp_ignore = 0
net.ipv4.conf.lo.arp_announce = 0
net.ipv4.conf.all.arp_ignore = 0
EOF
sysctl -p >/dev/null 2>&1
echo "[内核 优化] ==> OK"
}

function init_security(){        #[SELINUX关闭]
> /etc/issue  #清除系统信息
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g'  /etc/selinux/config
sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
setenforce 0 >/dev/null 2>&1
#systemctl stop firewalld.service
#systemctl disable firewalld.service
#yum install -y openssl openssh bash >/dev/null 2>&1
echo "[SELINUX关闭] ==> OK" 
}

function ubuntu_install_zanePerfor_github() { #ubuntu系统github源代码部署zanePerfor
if [[ "$install" == 'apt' ]];then 

apt update >> /dev/null
echo "[apt update] ==> OK"

timedatectl set-timezone Asia/Shanghai
echo "[设置上海时区Asia/Shanghai] ==> OK"

apt install -y net-tools vim wget curl nginx git nodejs npm zip unzip;apt install -y docker* >> /dev/null
echo "[curl nginx git nodejs npm zip unzip docker* ] ==> OK"

systemctl start docker;systemctl enable docker;systemctl is-enabled docker ;docker ps
echo "[start docker] ==> OK"

git clone https://github.com/wangweianger/zanePerfor.git >> /dev/null
echo "[git clone] ==> OK"

cd zanePerfor
node -v ; npm -v >> /dev/null
echo "[node -v ; npm -v] ==> OK"

npm install . >> /dev/null
echo "[npm install] ==> OK"

export hostIP=`hostname -i`
docker-compose up -d --build >> /dev/null
echo "[docker-compose up -d --build] ==> OK" 

docker ps
echo "根据情况修改 zanePerfor/config/config.default.js zanePerfor/config/config.prod.js 然后 npm start 启动项目 "
echo "[部署zanePerfor] ==> OK" 
fi
}

function ubuntu_install_zanePerfor_zip() { #ubuntu系统二开源代码部署zanePerfor
if [[ "$install" == 'apt' ]];then 

apt update >> /dev/null
echo "[apt update] ==> OK" 

timedatectl set-timezone Asia/Shanghai
echo "[设置上海时区Asia/Shanghai] ==> OK" 

apt install -y net-tools vim wget curl nginx git nodejs npm zip unzip >> /dev/null ;apt install -y docker* >> /dev/null
echo "[net-tools vim wget curl nginx git nodejs npm zip unzip docker* ] ==> OK" 

systemctl start docker;systemctl enable docker;systemctl is-enabled docker ;docker ps
echo "[start docker] ==> OK" 

wget https://transfer.sh/tev2dw/zanePerfor-ben.zip
unzip zanePerfor-ben.zip
echo "[zanePerfor-ben.zip 二开源代码解压] ==> OK" 

cat > /etc/nginx/nginx.conf                     << "EOF"
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;

#获取用户真实IP，并赋值给变量$clientRealIP
map $http_x_forwarded_for  $clientRealIp {
        ""      $remote_addr;
        ~^(?P<firstAddr>[0-9\.]+),?.*$  $firstAddr;
}

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
EOF
echo "[主配置生成 nginx.conf] ==> OK"

cat > /etc/nginx/conf.d/7001.conf               << "EOF"
server{
  listen 80;
  server_name img.18x18b.com;
  location / {

proxy_set_header Host $host;
proxy_set_header X-Real-IP $clientRealIp;
proxy_set_header REMOTE-HOST $clientRealIp;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass  http://127.0.0.1:7001; 
        access_log  /var/log/nginx/img.18x18b.com.log;
  }
}
EOF
echo "[主站 $server_name 配置生成 7001.conf] ==> OK"

sed -i "s/img.18x18b.com/${server_name}/g"  zanePerfor/config/config.prod.js
sed -i "s/img.18x18b.com/${server_name}/g"  zanePerfor/config/config.default.js
sed -i "s/img.18x18b.com/${server_name}/g"  /etc/nginx/conf.d/7001.conf 
echo "[修改项目和nginx配置域名为 ${server_name}] ==> OK" 
 
cd zanePerfor
npm install . >> /dev/null
echo "[构建项目依赖] ==> OK" 

export hostIP=`hostname -i`
docker-compose up -d --build >> /dev/null
echo "[构建docker镜像] ==> OK" 


sleep 15
npm start 
echo "[npm start] ==> OK" 

nginx ; nginx -t ; nginx -s reload >> /dev/null
echo "[nginx -s reload] ==> OK" 

curl -s https://$server_name | grep '前端性能监控平台'

echo "浏览器打开 https://$server_name "

fi
}

function centos_install_nginx() { #centos系统部署nginx
if [[ "$install" == 'yum' ]];then
yum update ; yum install -y nginx
fi
}

#依次导入函数
export -f init_ulimits           
export -f init_tomcat
export -f init_history
export -f init_ssh
export -f init_kernel
export -f init_security
export -f ubuntu_install_zanePerfor_zip

#依次执行函数
echo                "[系统初始化开始] ==> OK"
init_ulimits        #[ulimits 配置]
init_tomcat         #[tomcat 用户ssh密钥配置]  然后堡垒机运行jenks添加进去
init_kernel         #[内核 优化]
#init_history       #[history 优化]
#init_ssh           #[SSH 优化]
#init_security      #[SELINUX关闭]


echo                "[系统初始化结束] ==> OK"
echo "服务器公网ip `curl -s ifconfig.me`"
echo "服务器内网ip `hostname -i`"
echo "主机名 `hostname`"
echo "部署基础服务 zanePerfor"
ubuntu_install_zanePerfor_zip  
