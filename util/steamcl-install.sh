#!/bin/bash

set -eu;
shopt -s extglob;

. /etc/os-release

ESP_UUID=c12a7328-f81f-11d2-ba4b-00a0c93ec93b;
esp_uuid=;
esp_dev=;
esp_part=;
esp_mount=;
esp_id=;
esp_fs=;
boot_entries=;
distrib=$ID;

warn ()
{
    echo "$@" >&2;
}

############################################################################
# determine the location of the esp and its current mount point if any
find_esp ()
{
    esp_fs=;
    esp_id=;
    esp_dev=;
    esp_part=;
    esp_mount=;
    esp_uuid=;

    local part=;
    local dev=;
    local ptuid=;
    local fs=;
    local mount=;

    while read part dev ptuid fs mount;
    do
        if [ "$fs" != vfat ]; then continue; fi;

        if [ "$mount" = /esp ];
        then
            esp_fs="$fs";
            esp_id="$ptuid";
            esp_dev="$dev";
            esp_part="$part";
            esp_mount="$mount";
            esp_uuid="$ptuid";
            break;
        fi;
    done < <(lsblk -nlp -o NAME,PKNAME,PARTTYPE,FSTYPE,MOUNTPOINT);

    # doesn't look like the ESP, try again:
    if [ "$ESP_UUID" != "$esp_uuid" ];
    then
        while read part dev ptuid fs mount;
        do
            if [ "$fs"    != vfat        ]; then continue; fi;
            if [ "$ptuid" != "$ESP_UUID" ]; then continue; fi;

            esp_fs="$fs";
            esp_id="$ptuid";
            esp_dev="$dev";
            esp_part="$part";
            esp_mount="$mount";
            esp_uuid="$ptuid";
            break;
        done < <(lsblk -nlp -o NAME,PKNAME,PARTTYPE,FSTYPE,MOUNTPOINT);
    fi;

    if [ -z "$esp_dev" ] || [ -z "$esp_part" ];
    then
        warn "ESP not found by part-type ($ESP_UUID) or path (/esp)";
        return 1;
    fi;

    if [ -z "$mount" ];
    then
        warn "ESP on $esp_part is not mounted";
        return 1;
    fi;

    esp_part=${esp_part:${#esp_dev}};

    return 0;
}

############################################################################
# find matching efiboot entries:
find_boot_entries ()
{
    local distributor=${1:-debian}; shift;
    local dev=$1;                   shift;
    local part=${1:-999};           shift;
    local bootid=;
    local entry=;
    local label=;
    local epart=;
    local epath=;
    local edist=;

    boot_entries=;
    distributor=${distributor,,};

    while read -r bootid entry;
    do
        case $bootid in (Boot+([0-9])\*) true; ;; *) continue; esac;
        case $entry  in (*+([ 	])HD\(*) true; ;; *) continue; esac;

        bootid=${bootid%\*};
        label=${entry%%HD\(*};

        epart=${entry#*HD\(};
        epart=${epart%%,*}

        if [ ! ${epart:-0} -eq ${part} ]; then continue; fi;

        epath=${entry##*/File\(};
        epath=${epath%\)*};
        epath=${epath//\\/\/};

        edist=${epath#?(/)EFI/}
        edist=${edist%%/*};

        if [ "${edist,,}" = "$distributor" ];
        then
            local new_entry=${bootid#Boot}:$epath;
            boot_entries=$boot_entries${boot_entries:+ }${new_entry};
        fi;
    done < <(efibootmgr -v);
}


find_esp;
echo "$esp_fs $esp_uuid on $esp_dev $esp_part ($esp_mount)";
find_boot_entries $distrib $esp_dev $esp_part;
echo Boot entries for $distrib on $esp_dev GPT\#$esp_part
echo "[$boot_entries]";
