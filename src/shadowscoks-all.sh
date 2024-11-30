#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Auto install Shadowsocks-Python Server
# System Required:  Debian7+, Ubuntu12+

red='\033[0;31m'
green='\033[0;32m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

cur_dir=$(pwd)

shadowsocks_python_file="shadowsocks-master"
shadowsocks_python_url="https://github.com/Jv0id/Shadowsocks/raw/master/src/pack/shadowsocks-master.zip"
shadowsocks_python_init="/etc/init.d/shadowsocks-python"
shadowsocks_python_config="/etc/shadowsocks-python/config.json"
shadowsocks_python_debian="https://raw.githubusercontent.com/Jv0id/Shadowsocks/master/src/ssr/shadowsocks-debian"
libsodium_file="libsodium-1.0.17"
libsodium_url="https://github.com/Jv0id/Shadowsocks/raw/master/src/pack/libsodium-1.0.17.tar.gz"

install_dependencies() {
  apt_depends=(
    gettext build-essential unzip gzip python3 python3-dev python3-setuptools curl openssl libssl-dev
    autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
  )

  apt-get -y update
  for depend in ${apt_depends[@]}; do
    echo -e "[${green}Info${plain}] Starting to install package ${depend}"
    apt-get -y install ${depend} >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install ${depend}"
  done
}

install_libsodium() {
  if [ ! -f /usr/lib/libsodium.a ]; then
    cd ${cur_dir}
    wget --no-check-certificate -c -t3 -T60 -O ${libsodium_file}.tar.gz ${libsodium_url}
    tar zxf ${libsodium_file}.tar.gz
    cd ${libsodium_file}
    ./configure --prefix=/usr && make && make install
    if [ $? -ne 0 ]; then
      echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
      exit 1
    fi
  else
    echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
  fi
}

download_files() {
  cd ${cur_dir}
  wget --no-check-certificate -c -t3 -T60 -O ${shadowsocks_python_file}.zip ${shadowsocks_python_url}
  if [ ! -f ${shadowsocks_python_file}.zip ]; then
    echo -e "[${red}Error${plain}] Failed to download ${shadowsocks_python_file}.zip"
    exit 1
  fi
  wget --no-check-certificate -c -t3 -T60 -O ${shadowsocks_python_init} ${shadowsocks_python_debian}
  if [ ! -f ${shadowsocks_python_init} ]; then
    echo -e "[${red}Error${plain}] Failed to download ${shadowsocks_python_init}"
    exit 1
  fi
}

config_shadowsocks() {
  if [ ! -d "$(dirname ${shadowsocks_python_config})" ]; then
    mkdir -p $(dirname ${shadowsocks_python_config})
  fi
  cat >${shadowsocks_python_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_port":8388,
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"password",
    "timeout":300,
    "method":"aes-256-cfb",
    "fast_open":false
}
EOF
}

install_shadowsocks_python() {
  cd ${cur_dir}
  if [ ! -f ${shadowsocks_python_file}.zip ]; then
    echo -e "[${red}Error${plain}] ${shadowsocks_python_file}.zip not found. Exiting..."
    exit 1
  fi
  unzip -q ${shadowsocks_python_file}.zip
  if [ ! -d ${shadowsocks_python_file} ]; then
    echo -e "[${red}Error${plain}] Failed to unzip ${shadowsocks_python_file}.zip"
    exit 1
  fi
  cd ${shadowsocks_python_file}
  python3 setup.py install --record /usr/local/shadowsocks_python.log
  chmod +x ${shadowsocks_python_init}
  update-rc.d -f $(basename ${shadowsocks_python_init}) defaults
}

install_cleanup() {
  cd ${cur_dir}
  rm -rf ${shadowsocks_python_file} ${shadowsocks_python_file}.zip ${libsodium_file} ${libsodium_file}.tar.gz
}

install_shadowsocks() {
  install_dependencies
  install_libsodium
  download_files
  config_shadowsocks
  install_shadowsocks_python
  install_cleanup
  ${shadowsocks_python_init} start
  echo -e "[${green}Info${plain}] Shadowsocks-Python server install completed!"
}

uninstall_shadowsocks_python() {
  printf "Are you sure uninstall ${red}Shadowsocks-Python${plain}? [y/n]\n"
  read -e -p "(default: n):" answer
  [ -z ${answer} ] && answer="n"
  if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
    ${shadowsocks_python_init} status >/dev/null 2>&1 && ${shadowsocks_python_init} stop
    update-rc.d -f $(basename ${shadowsocks_python_init}) remove
    rm -fr $(dirname ${shadowsocks_python_config})
    rm -f ${shadowsocks_python_init}
    rm -f /var/log/shadowsocks.log
    cat /usr/local/shadowsocks_python.log | xargs rm -rf
    rm -f /usr/local/shadowsocks_python.log
    echo -e "[${green}Info${plain}] Shadowsocks-Python uninstall success"
  else
    echo -e "[${green}Info${plain}] Shadowsocks-Python uninstall cancelled, nothing to do..."
  fi
}

action=$1
[ -z $1 ] && action=install
case "${action}" in
install | uninstall)
  ${action}_shadowsocks_python
  ;;
*)
  echo "Arguments error! [${action}]"
  echo "Usage: $(basename $0) [install|uninstall]"
  ;;
esac
