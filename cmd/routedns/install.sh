#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}error：${plain} The script must be run as root！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
else
    echo -e "${red}The system version was not detected, please contact the script author！${plain}\n" && exit 1
fi

arch=$(arch)

if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64-v8a"
elif [[ $arch == "s390x" ]]; then
    arch="s390x"
else
    arch="64"
    echo -e "${red}Detect schema failed, use default schema: ${arch}${plain}"
fi

echo "architecture: ${arch}"

if [ "$(getconf WORD_BIT)" != '32' ] && [ "$(getconf LONG_BIT)" != '64' ] ; then
    echo "This software does not support 32-bit system (x86), please use 64-bit system (x86_64), if the detection is wrong, please contact the author"
    exit 2
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        echo -e "${red}Please use CentOS 7 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}Please use Ubuntu 16 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}Please use Debian 8 or later！${plain}\n" && exit 1
    fi
fi

install_base() {
    if [[ x"${release}" == x"centos" ]]; then
        yum install epel-release -y
        yum install wget curl unzip tar crontabs socat -y
    else
        apt update -y
        apt install wget curl unzip tar cron socat -y
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if [[ ! -f /etc/systemd/system/RouteDns.service ]]; then
        return 2
    fi
    temp=$(systemctl status RouteDns | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

install_acme() {
    curl https://get.acme.sh | sh
}

install_XrayR() {
    if [[ -e /usr/local/RouteDns/ ]]; then
        rm /usr/local/RouteDns/ -rf
    fi

    mkdir /usr/local/RouteDns/ -p
	cd /usr/local/RouteDns/

    if  [ $# == 0 ] ;then
        last_version=$(curl -Ls "https://api.github.com/repos/i-panel/RouteDns/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${red}Failed to detect RouteDns version, it may be beyond the Github API limit, please try again later, or manually specify the RouteDns version to install${plain}"
            exit 1
        fi
        echo -e "The latest version of RouteDns has been detected：${last_version}，start installation"
        wget -q -N --no-check-certificate -O /usr/local/RouteDns/RouteDns-linux.zip https://github.com/i-panel/RouteDns/releases/download/${last_version}/RouteDns-linux-${arch}.zip
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Failed to download RouteDns, please make sure your server can download files from Github${plain}"
            exit 1
        fi
    else
        if [[ $1 == v* ]]; then
            last_version=$1
	else
	    last_version="v"$1
	fi
        url="https://github.com/i-panel/RouteDns/releases/download/${last_version}/RouteDns-linux-${arch}.zip"
        echo -e "start installation RouteDns ${last_version}"
        wget -q -N --no-check-certificate -O /usr/local/RouteDns/RouteDns-linux.zip ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}download RouteDns ${last_version} Failed, make sure this version exists${plain}"
            exit 1
        fi
    fi

    unzip RouteDns-linux.zip
    rm RouteDns-linux.zip -f
    chmod +x RouteDns
    mkdir /etc/RouteDns/ -p
    rm /etc/systemd/system/RouteDns.service -f
    file="https://github.com/i-panel/RouteDns/raw/master/RouteDns.service"
    wget -q -N --no-check-certificate -O /etc/systemd/system/RouteDns.service ${file}
    #cp -f XrayR.service /etc/systemd/system/

    wget -q -N --no-check-certificate -O /etc/RouteDns/geoip.dat https://raw.githubusercontent.com/Chocolate4u/Iran-v2ray-rules/release/geoip.dat
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to download RouteDns geoip database, please make sure your server can download files from Github${plain}"
        exit 1
    fi

    wget -q -N --no-check-certificate -O /etc/RouteDns/geosite.dat https://raw.githubusercontent.com/Chocolate4u/Iran-v2ray-rules/release/geosite.dat
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to download RouteDns geosite database, please make sure your server can download files from Github${plain}"
        exit 1
    fi

    wget -q -N --no-check-certificate -O /etc/RouteDns/config.toml https://raw.githubusercontent.com/i-panel/RouteDns/refs/heads/master/cmd/routedns/example-config/blocklist-panel.toml
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to download RouteDns config, please make sure your server can download files from Github${plain}"
        exit 1
    fi

    systemctl daemon-reload
    systemctl stop RouteDns
    systemctl enable RouteDns
    echo -e "${green}RouteDns ${last_version}${plain} The installation is complete, and it has been set to start automatically at boot"


    if [[ ! -f /etc/RouteDns/config.toml ]]; then
        cp config.toml /etc/RouteDns/
        echo -e ""
        echo -e "Fresh installation, please refer to the tutorial first：https://github.com/XrayR-project/RouteDns，Configure necessary content"
    else
        systemctl start RouteDns
        sleep 2
        check_status
        echo -e ""
        if [[ $? == 0 ]]; then
            echo -e "${green}RouteDns restart successfully${plain}"
        else
            echo -e "${red}RouteDns It may fail to start, please use RouteDns log to view the log information later, if it cannot start, the configuration format may have been changed, please go to the wiki to view：https://github.com/XrayR-project/RouteDns/wiki${plain}"
        fi
    fi

    curl -o /usr/bin/RouteDns -Ls https://raw.githubusercontent.com/i-panel/RouteDns/master/RouteDns.sh
    chmod +x /usr/bin/RouteDns
    ln -s /usr/bin/RouteDns /usr/bin/routedns # 小写兼容
    chmod +x /usr/bin/routedns
    cd $cur_dir
    rm -f install.sh
    echo -e ""
    echo "How to use RouteDns management scripts (compatible with routedns execution, case insensitive): "
    echo "------------------------------------------"
    echo "RouteDns                    - Show admin menu (more features)"
    echo "RouteDns start              - start RouteDns"
    echo "RouteDns stop               - stop RouteDns"
    echo "RouteDns restart            - restart RouteDns"
    echo "RouteDns status             - View RouteDns status"
    echo "RouteDns enable             - Set RouteDns to start automatically at boot"
    echo "RouteDns disable            - Disable RouteDns autostart"
    echo "RouteDns log                - View RouteDns logs"
    echo "RouteDns update             - Update RouteDns"
    echo "RouteDns update x.x.x       - Update the specified version of RouteDns"
    echo "RouteDns config             - Show configuration file content"
    echo "RouteDns install            - Install RouteDns"
    echo "RouteDns uninstall          - Uninstall RouteDns"
    echo "RouteDns version            - View RouteDns version"
    echo "------------------------------------------"
}

echo -e "${green}start installation${plain}"
install_base
# install_acme
install_RouteDns $1