#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Auto install Shadowsocks-python Server
#
# Origin written by Jv0id <www.jpjny.xyz>
# Modified by Hamakaze <hamakaze.top>
#
# System Required: Debian7+, Ubuntu12+

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

cur_dir=$(pwd)
software=(Shadowsocks-Python)

libsodium_file="libsodium-1.0.17"
libsodium_url="https://raw.githubusercontent.com/Hamakaze1s/Shadowsocks-init/refs/heads/develop/src/pack/libsodium-1.0.17.tar.gz"

shadowsocks_python_file="shadowsocks-master"
shadowsocks_python_url="https://raw.githubusercontent.com/Hamakaze1s/Shadowsocks-init/refs/heads/develop/src/pack/shadowsocks-master.zip"
shadowsocks_python_init="/etc/init.d/shadowsocks-python"
shadowsocks_python_config="/etc/shadowsocks-python/config.json"
shadowsocks_python_debian="https://raw.githubusercontent.com/Hamakaze1s/Shadowsocks-init/refs/heads/develop/src/ssr/shadowsocks-debian"


# Stream Ciphers
common_ciphers=(
  aes-256-gcm
  aes-192-gcm
  aes-128-gcm
  aes-256-ctr
  aes-192-ctr
  aes-128-ctr
  aes-256-cfb
  aes-192-cfb
  aes-128-cfb
  camellia-128-cfb
  camellia-192-cfb
  camellia-256-cfb
  xchacha20-ietf-poly1305
  chacha20-ietf-poly1305
  chacha20-ietf
  chacha20
  salsa20
  rc4-md5
)

# libev obfuscating
obfs_libev=(http tls)
# initialization parameter
libev_obfs=""

disable_selinux() {
  if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
  fi
}

check_sys() {
  local checkType=$1
  local value=$2

  local release=''
  local systemPackage=''

  if [[ -f /etc/redhat-release ]]; then
    release="centos"
    systemPackage="yum"
  elif grep -Eqi "debian|raspbian" /etc/issue; then
    release="debian"
    systemPackage="apt"
  elif grep -Eqi "ubuntu" /etc/issue; then
    release="ubuntu"
    systemPackage="apt"
  elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
    release="centos"
    systemPackage="yum"
  elif grep -Eqi "debian|raspbian" /proc/version; then
    release="debian"
    systemPackage="apt"
  elif grep -Eqi "ubuntu" /proc/version; then
    release="ubuntu"
    systemPackage="apt"
  elif grep -Eqi "centos|red hat|redhat" /proc/version; then
    release="centos"
    systemPackage="yum"
  fi

  if [[ "${checkType}" == "sysRelease" ]]; then
    if [ "${value}" == "${release}" ]; then
      return 0
    else
      return 1
    fi
  elif [[ "${checkType}" == "packageManager" ]]; then
    if [ "${value}" == "${systemPackage}" ]; then
      return 0
    else
      return 1
    fi
  fi
}

version_ge() {
  test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt() {
  test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_kernel_version() {
  local kernel_version=$(uname -r | cut -d- -f1)
  if version_gt "${kernel_version}" 3.7.0; then
    return 0
  else
    return 1
  fi
}

check_kernel_headers() {
  if check_sys packageManager yum; then
    if rpm -qa | grep -q headers-$(uname -r); then
      return 0
    else
      return 1
    fi
  elif check_sys packageManager apt; then
    if dpkg -s linux-headers-$(uname -r) >/dev/null 2>&1; then
      return 0
    else
      return 1
    fi
  fi
  return 1
}

getversion() {
  if [[ -s /etc/redhat-release ]]; then
    grep -oE "[0-9.]+" /etc/redhat-release
  else
    grep -oE "[0-9.]+" /etc/issue
  fi
}

centosversion() {
  if check_sys sysRelease centos; then
    local code=$1
    local version="$(getversion)"
    local main_ver=${version%%.*}
    if [ "$main_ver" == "$code" ]; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

autoconf_version() {
  if [ ! "$(command -v autoconf)" ]; then
    echo -e "[${green}Info${plain}] Starting install package autoconf"
    if check_sys packageManager yum; then
      yum install -y autoconf >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
    elif check_sys packageManager apt; then
      apt-get -y update >/dev/null 2>&1
      apt-get -y install autoconf >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
    fi
  fi
  local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
  if version_ge "${autoconf_ver}" 2.67; then
    return 0
  else
    return 1
  fi
}

get_ip() {
  local IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
  [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
  [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipinfo.io/ip)
  echo ${IP}
}

get_ipv6() {
  local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
  [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver() {
  libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
  [ -z ${libev_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed" && exit 1
}

get_opsy() {
  [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
  [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
  [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

is_64bit() {
  if [ $(getconf WORD_BIT) = '32' ] && [ $(getconf LONG_BIT) = '64' ]; then
    return 0
  else
    return 1
  fi
}

debianversion() {
  if check_sys sysRelease debian; then
    local version=$(get_opsy)
    local code=${1}
    local main_ver=$(echo ${version} | sed 's/[^0-9]//g')
    if [ "${main_ver}" == "${code}" ]; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

download() {
  local filename=$(basename $1)
  if [ -f ${1} ]; then
    echo "${filename} [found]"
  else
    echo "${filename} not found, download now..."
    wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error${plain}] Download ${filename} failed."
      exit 1
    fi
  fi
}

download_files() {
  cd ${cur_dir}
  
  download "${shadowsocks_python_file}.zip" "${shadowsocks_python_url}"
  if check_sys packageManager yum; then
    download "${shadowsocks_python_init}" "${shadowsocks_python_centos}"
  elif check_sys packageManager apt; then
    download "${shadowsocks_python_init}" "${shadowsocks_python_debian}"
  fi

}

get_char() {
  SAVEDSTTY=$(stty -g)
  stty -echo
  stty cbreak
  dd if=/dev/tty bs=1 count=1 2>/dev/null
  stty -raw
  stty echo
  stty $SAVEDSTTY
}

error_detect_depends() {
  local command=$1
  local depend=$(echo "${command}" | awk '{print $4}')
  echo -e "[${green}Info${plain}] Starting to install package ${depend}"
  ${command} >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
    echo "Please visit: https://hamakaze.top and contact."
    exit 1
  fi
}

config_firewall() {
  if centosversion 6; then
    /etc/init.d/iptables status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      iptables -L -n | grep -i ${shadowsocksport} >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
        /etc/init.d/iptables save
        /etc/init.d/iptables restart
      else
        echo -e "[${green}Info${plain}] port ${green}${shadowsocksport}${plain} already be enabled."
      fi
    else
      echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
    fi
  elif centosversion 7; then
    systemctl status firewalld >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      default_zone=$(firewall-cmd --get-default-zone)
      firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
      firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
      firewall-cmd --reload
    else
      echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
    fi
  fi
}

config_shadowsocks() {

  if check_kernel_version && check_kernel_headers; then
    fast_open="true"
  else
    fast_open="false"
  fi


  if [ ! -d "$(dirname ${shadowsocks_python_config})" ]; then
    mkdir -p $(dirname ${shadowsocks_python_config})
  fi
  cat >${shadowsocks_python_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF

}

install_dependencies() {
  if check_sys packageManager yum; then
    echo -e "[${green}Info${plain}] Checking the EPEL repository..."
    if [ ! -f /etc/yum.repos.d/epel.repo ]; then
      yum install -y epel-release >/dev/null 2>&1
    fi
    [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
    [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils >/dev/null 2>&1
    [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable epel >/dev/null 2>&1
    echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."

    yum_depends=(
      unzip gzip openssl openssl-devel gcc python python-devel python-setuptools pcre pcre-devel libtool libevent
      autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
      libev-devel c-ares-devel git qrencode
    )
    for depend in ${yum_depends[@]}; do
      error_detect_depends "yum -y install ${depend}"
    done
  elif check_sys packageManager apt; then
    apt_depends=(
      gettext build-essential unzip gzip python3 python3-dev python3-setuptools curl openssl libssl-dev
      autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
    )

    apt-get -y update
    for depend in ${apt_depends[@]}; do
      error_detect_depends "apt-get -y install ${depend}"
    done
  fi
}

install_check() {
  if check_sys packageManager yum || check_sys packageManager apt; then
    if centosversion 5; then
      return 1
    fi
    return 0
  else
    return 1
  fi
}


install_prepare_password() {
  echo "Please enter password for Shadowsocks-Python"
  read -e -p "(Default password: 123456):" shadowsockspwd
  [ -z "${shadowsockspwd}" ] && shadowsockspwd="123456"
  echo
  echo "password = ${shadowsockspwd}"
  echo
}

install_prepare_port() {
  while true; do
    dport=$(shuf -i 9000-19999 -n 1)
    echo -e "Please enter a port for Shadowsocks-Python [1-65535]"
    read -e -p "(Default port: ${dport}):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
      if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
        echo
        echo "port = ${shadowsocksport}"
        echo
        break
      fi
    fi
    echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
  done
}

install_prepare_cipher() {
  while true; do
    echo -e "Please select stream cipher for Shadowsocks-Python:"

    for ((i = 1; i <= ${#common_ciphers[@]}; i++)); do
      hint="${common_ciphers[$i - 1]}"
      echo -e "${green}${i}${plain}) ${hint}"
    done
    read -e -p "Which cipher you'd select(Default: ${common_ciphers[0]}):" pick
    [ -z "$pick" ] && pick=1
    expr ${pick} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error${plain}] Please enter a number"
      continue
    fi
    if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
      echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#common_ciphers[@]}"
      continue
    fi
    shadowsockscipher=${common_ciphers[$pick - 1]}


    echo
    echo "cipher = ${shadowsockscipher}"
    echo
    break
  done
}



install_prepare() {

  if ! install_check; then
    echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
    echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
    exit 1
  fi
  clear

  install_prepare_password
  install_prepare_port
  install_prepare_cipher

  echo
  echo "Press any key to start...or Press Ctrl+C to cancel"
  char=$(get_char)

}

install_libsodium() {
  if [ ! -f /usr/lib/libsodium.a ]; then
    cd ${cur_dir}
    download "${libsodium_file}.tar.gz" "${libsodium_url}"
    tar zxf ${libsodium_file}.tar.gz
    cd ${libsodium_file}
    ./configure --prefix=/usr && make && make install
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
      install_cleanup
      exit 1
    fi
  else
    echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
  fi
}


install_shadowsocks_python() {
  cd ${cur_dir}
  unzip -q ${shadowsocks_python_file}.zip
  if [ $? -ne 0 ]; then
    echo -e "[${red}Error${plain}] unzip ${shadowsocks_python_file}.zip failed, please check unzip command."
    install_cleanup
    exit 1
  fi

  cd ${shadowsocks_python_file}
  python3 setup.py install --record /usr/local/shadowsocks_python.log

  if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
    chmod +x ${shadowsocks_python_init}
    local service_name=$(basename ${shadowsocks_python_init})
    if check_sys packageManager yum; then
      chkconfig --add ${service_name}
      chkconfig ${service_name} on
    elif check_sys packageManager apt; then
      update-rc.d -f ${service_name} defaults
    fi
  else
    echo
    echo -e "[${red}Error${plain}] ${software[0]} install failed."
    echo "Please visit: https://hamakaze.top and contact."
    install_cleanup
    exit 1
  fi
}

install_completed_python() {
  clear
  ${shadowsocks_python_init} start
  echo
  echo -e "Congratulations, ${green}${software[0]}${plain} server install completed!"
  echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
  echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
  echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
  echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
}

qr_generate_python() {
  if [ "$(command -v qrencode)" ]; then
    local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
    local qr_code="ss://${tmp}"
    echo
    echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
    echo -e "${green} ${qr_code} ${plain}"
    echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_python_qr.png
    echo "Your QR Code has been saved as a PNG file path:"
    echo -e "${green} ${cur_dir}/shadowsocks_python_qr.png ${plain}"
  fi
}

install_main() {
  install_libsodium
  if ! ldconfig -p | grep -wq "/usr/lib"; then
    echo "/usr/lib" >/etc/ld.so.conf.d/lib.conf
  fi
  ldconfig

  
  install_shadowsocks_python
  install_completed_python
  qr_generate_python

  echo
  echo "Welcome to visit: https://hamakaze.top"
  echo "Enjoy it!"
  echo
}

install_cleanup() {
  cd ${cur_dir}
  rm -rf simple-obfs
  rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
  rm -rf ${shadowsocks_python_file} ${shadowsocks_python_file}.zip
}

install_shadowsocks() {
  disable_selinux
  install_prepare
  install_dependencies
  download_files
  config_shadowsocks
  if check_sys packageManager yum; then
    config_firewall
  fi
  install_main
  install_cleanup
}

uninstall_shadowsocks_python() {
  printf "Are you sure uninstall ${red}${software[0]}${plain}? [y/n]\n"
  read -e -p "(default: n):" answer
  [ -z ${answer} ] && answer="n"
  if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
    ${shadowsocks_python_init} status >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      ${shadowsocks_python_init} stop
    fi
    local service_name=$(basename ${shadowsocks_python_init})
    if check_sys packageManager yum; then
      chkconfig --del ${service_name}
    elif check_sys packageManager apt; then
      update-rc.d -f ${service_name} remove
    fi

    rm -fr $(dirname ${shadowsocks_python_config})
    rm -f ${shadowsocks_python_init}
    rm -f /var/log/shadowsocks.log
    if [ -f /usr/local/shadowsocks_python.log ]; then
      cat /usr/local/shadowsocks_python.log | xargs rm -rf
      rm -f /usr/local/shadowsocks_python.log
    fi
    echo -e "[${green}Info${plain}] ${software[0]} uninstall success"
  else
    echo
    echo -e "[${green}Info${plain}] ${software[0]} uninstall cancelled, nothing to do..."
    echo
  fi
}

uninstall_shadowsocks() {
    if [ -f ${shadowsocks_python_init} ]; then
      uninstall_shadowsocks_python
    else
      echo -e "[${red}Error${plain}] Shadowsocks-python not installed, please check it and try again."
      echo
      exit 1
    fi
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "${action}" in
install | uninstall)
  ${action}_shadowsocks
  ;;
*)
  echo "Arguments error! [${action}]"
  echo "Usage: $(basename $0) [install|uninstall]"
  ;;
esac