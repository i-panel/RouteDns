#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

version="v1.0.0"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}error: ${plain} The root user must be used to run this script!\n" && exit 1

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
    echo -e "${red}System version not detected, please contact the script author!${plain}\n" && exit 1
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
        echo -e "${red}please use CentOS 7 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        echo -e "${red}please use Ubuntu 16 or later system！${plain}\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        echo -e "${red}please use Debian 8 or later system！${plain}\n" && exit 1
    fi
fi

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [default$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "whether to restart RouteDns" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}Press enter to return to the main menu: ${plain}" && read temp
    show_menu
}

install() {
    bash <(curl -Ls https://raw.githubusercontent.com/i-panel/RouteDns/master/install.sh)
    if [[ $? == 0 ]]; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    if [[ $# == 0 ]]; then
        echo && echo -n -e "Enter the specified version (default latest version): " && read version
    else
        version=$2
    fi
#    confirm "本功能会强制重装当前最新版，数据不会丢失，是否继续?" "n"
#    if [[ $? != 0 ]]; then
#        echo -e "${red}已取消${plain}"
#        if [[ $1 != 0 ]]; then
#            before_show_menu
#        fi
#        return 0
#    fi
    bash <(curl -Ls https://raw.githubusercontent.com/i-panel/RouteDns/master/install.sh) $version
    if [[ $? == 0 ]]; then
        echo -e "${green}The update is complete and RouteDns has automatically restarted, please use RouteDns log to view the running log ${plain}"
        exit
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

config() {
    echo "RouteDns It will automatically try to restart after modifying the configuration"
    vi /etc/RouteDns/config.toml
    sleep 2
    check_status
    case $? in
        0)
            echo -e "RouteDns state: ${green} has been run ${plain}"
            ;;
        1)
            echo -e "It is detected that you have not started RouteDns or RouteDns failed to restart automatically, check the log？[Y/n]" && echo
            read -e -p "(default: y):" yn
            [[ -z ${yn} ]] && yn="y"
            if [[ ${yn} == [Yy] ]]; then
               show_log
            fi
            ;;
        2)
            echo -e "RouteDns status: ${red}Not Installed${plain}"
    esac
}

uninstall() {
    confirm "Are you sure you want to uninstall RouteDns?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    systemctl stop RouteDns
    systemctl disable RouteDns
    rm /etc/systemd/system/RouteDns.service -f
    systemctl daemon-reload
    systemctl reset-failed
    rm /etc/RouteDns/ -rf
    rm /usr/local/RouteDns/ -rf

    echo ""
    echo -e "The uninstall is successful, if you want to delete this script, run it after exiting the script ${green}rm /usr/bin/RouteDns -f${plain} to delete"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "${green}RouteDns Already running, no need to start again, if you need to restart, please select restart${plain}"
    else
        systemctl start RouteDns
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            echo -e "${green}RouteDns The startup is successful, please use RouteDns log to view the running log${plain}"
        else
            echo -e "${red}RouteDns startup may fail, please use RouteDns log to check the log information later${plain}"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    systemctl stop RouteDns
    sleep 2
    check_status
    if [[ $? == 1 ]]; then
        echo -e "${green}RouteDns stop success${plain}"
    else
        echo -e "${red}RouteDns failed to stop, probably because the stop time exceeded two seconds, please check the log information later${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    systemctl restart RouteDns
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        echo -e "${green}RouteDns restarted successfully, please use RouteDns log to view the running log${plain}"
    else
        echo -e "${red}RouteDns may fail to start, please use RouteDns log to view log information later${plain}"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    systemctl status RouteDns --no-pager -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    systemctl enable RouteDns
    if [[ $? == 0 ]]; then
        echo -e "${green}RouteDns Set the boot to start automatically${plain}"
    else
        echo -e "${red}RouteDns failed to set autostart${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    systemctl disable RouteDns
    if [[ $? == 0 ]]; then
        echo -e "${green}RouteDns Cancellation of automatic startup${plain}"
    else
        echo -e "${red}RouteDns failed to cancel autostart${plain}"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    journalctl -u RouteDns.service -e --no-pager -f
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

install_bbr() {
    bash <(curl -L -s https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh)
    #if [[ $? == 0 ]]; then
    #    echo ""
    #    echo -e "${green}安装 bbr 成功，请重启服务器${plain}"
    #else
    #    echo ""
    #    echo -e "${red}下载 bbr 安装脚本失败，请检查本机能否连接 Github${plain}"
    #fi

    #before_show_menu
}

update_shell() {
    wget -O /usr/bin/RouteDns -N --no-check-certificate https://raw.githubusercontent.com/i-panel/RouteDns/master/RouteDns.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "${red}Failed to download the script, please check whether the machine can connect to Github${plain}"
        before_show_menu
    else
        chmod +x /usr/bin/RouteDns
        echo -e "${green}The upgrade script was successful, please run the script again${plain}" && exit 0
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

check_enabled() {
    temp=$(systemctl is-enabled RouteDns)
    if [[ x"${temp}" == x"enabled" ]]; then
        return 0
    else
        return 1;
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${red}RouteDns already installed, please do not repeat the installation${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${red}Please install RouteDns first${plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
        0)
            echo -e "RouteDns status: ${green}has been run${plain}"
            show_enable_status
            ;;
        1)
            echo -e "RouteDns status: ${yellow}not running${plain}"
            show_enable_status
            ;;
        2)
            echo -e "RouteDns status: ${red}Not Installed${plain}"
    esac
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "Whether to start automatically: ${green}yes${plain}"
    else
        echo -e "Whether to start automatically: ${red}no${plain}"
    fi
}

show_XrayR_version() {
    echo -n "RouteDns version："
    /usr/local/RouteDns/RouteDns -version
    echo ""
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_usage() {
    echo "RouteDns How to use the management script: "
    echo "------------------------------------------"
    echo "RouteDns              - Show admin menu (more features)"
    echo "RouteDns start        - start RouteDns"
    echo "RouteDns stop         - stop RouteDns"
    echo "RouteDns restart      - restart RouteDns"
    echo "RouteDns status       - Check RouteDns status"
    echo "RouteDns enable       - Set RouteDns to start automatically at boot"
    echo "RouteDns disable      - Disable RouteDns autostart"
    echo "RouteDns log          - View RouteDns logs"
    echo "RouteDns update       - Update RouteDns"
    echo "RouteDns update x.x.x - Update the specified version of RouteDns"
    echo "RouteDns install      - Install RouteDns"
    echo "RouteDns uninstall    - uninstall RouteDns"
    echo "RouteDns version      - View RouteDns version"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
  ${green}XrayR backend management script，${plain}${red}not applicabledocker${plain}
--- https://github.com/i-panel/RouteDns ---
  ${green}0.${plain} Change setting
————————————————
  ${green}1.${plain} Install RouteDns
  ${green}2.${plain} renew RouteDns
  ${green}3.${plain} uninstall RouteDns
————————————————
  ${green}4.${plain} start RouteDns
  ${green}5.${plain} stop RouteDns
  ${green}6.${plain} reboot RouteDns
  ${green}7.${plain} Check RouteDns status
  ${green}8.${plain} View RouteDns logs
————————————————
  ${green}9.${plain} Set RouteDns to start automatically at boot
 ${green}10.${plain} Disable RouteDns autostart
————————————————
 ${green}11.${plain} One-click install bbr (latest kernel)
 ${green}12.${plain} View RouteDns version 
 ${green}13.${plain} Upgrade maintenance script
 "
 #后续更新可加入上方字符串中
    show_status
    echo && read -p "Please enter selection [0-13]: " num

    case "${num}" in
        0) config
        ;;
        1) check_uninstall && install
        ;;
        2) check_install && update
        ;;
        3) check_install && uninstall
        ;;
        4) check_install && start
        ;;
        5) check_install && stop
        ;;
        6) check_install && restart
        ;;
        7) check_install && status
        ;;
        8) check_install && show_log
        ;;
        9) check_install && enable
        ;;
        10) check_install && disable
        ;;
        11) install_bbr
        ;;
        12) check_install && show_RouteDns_version
        ;;
        13) update_shell
        ;;
        *) echo -e "${red}Please enter the correct number [0-12]${plain}"
        ;;
    esac
}


if [[ $# > 0 ]]; then
    case $1 in
        "start") check_install 0 && start 0
        ;;
        "stop") check_install 0 && stop 0
        ;;
        "restart") check_install 0 && restart 0
        ;;
        "status") check_install 0 && status 0
        ;;
        "enable") check_install 0 && enable 0
        ;;
        "disable") check_install 0 && disable 0
        ;;
        "log") check_install 0 && show_log 0
        ;;
        "update") check_install 0 && update 0 $2
        ;;
        "config") config $*
        ;;
        "install") check_uninstall 0 && install 0
        ;;
        "uninstall") check_install 0 && uninstall 0
        ;;
        "version") check_install 0 && show_RouteDns_version 0
        ;;
        "update_shell") update_shell
        ;;
        *) show_usage
    esac
else
    show_menu
fi