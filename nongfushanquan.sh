#!/bin/bash

# 源目录
BMV2_SRC_DIR="./p4src/v1model"
TNA_SRC_DIR="./p4src/tna"

# 目标基础目录
DEST_BASE="/home/onos/mysql/basic-multi-modal/src/main/resources/p4c-out"

# 定义所有部分及其固定顺序
PARTS=("IP" "ID" "GEO" "MF" "NDN" "FLEXIP")
declare -A PART_ORDER
for i in "${!PARTS[@]}"; do
    PART_ORDER["${PARTS[i]}"]=$((i+1))
done

# 函数：将任意顺序的组合名称转换为固定顺序
normalize_combo() {
    local input=$1
    local -a parts
    IFS='_' read -ra parts <<< "$input"

    # 按固定顺序排序
    local -a sorted_parts
    for part in "${PARTS[@]}"; do
        for p in "${parts[@]}"; do
            if [[ "$p" == "$part" ]]; then
                sorted_parts+=("$p")
                break
            fi
        done
    done

    # 重新拼接
    local normalized
    printf -v normalized "%s_" "${sorted_parts[@]}"
    normalized="${normalized%_}"  # 去除末尾的_
    echo "$normalized"
}

# 处理bmv2目录
for bmv2_dir in "${BMV2_SRC_DIR}"/bmv2_*; do
    if [[ -d "$bmv2_dir" ]]; then
        # 提取组合部分
        base_name=$(basename "$bmv2_dir")
        combo_part="${base_name#bmv2_}"

        # 标准化组合名称
        normalized_combo=$(normalize_combo "$combo_part")

        # 目标目录
        dest_dir="${DEST_BASE}/${normalized_combo}/bmv2"
        mkdir -p "$dest_dir"

        # 复制文件
        cp "${bmv2_dir}/bmv2.json" "${bmv2_dir}/p4info.txt" "$dest_dir" 2>/dev/null && \
            echo "Copied BMV2 files from $bmv2_dir to $dest_dir" || \
            echo "Warning: Missing files in $bmv2_dir"

        # 重命名源目录（如果需要）
        new_bmv2_dir="${BMV2_SRC_DIR}/bmv2_${normalized_combo}"
        if [[ "$bmv2_dir" != "$new_bmv2_dir" ]]; then
            mv "$bmv2_dir" "$new_bmv2_dir"
            echo "Renamed $bmv2_dir to $new_bmv2_dir"
        fi
    fi
done

# 处理TNA目录
for tna_dir in "${TNA_SRC_DIR}"/tofino_*; do
    if [[ -d "$tna_dir" ]]; then
        # 提取组合部分
        base_name=$(basename "$tna_dir")
        combo_part="${base_name#tofino_}"

        # 标准化组合名称
        normalized_combo=$(normalize_combo "$combo_part")

        # 目标目录
        dest_dir="${DEST_BASE}/${normalized_combo}/tna"
        mkdir -p "$dest_dir"

        # 复制文件
        cp "${tna_dir}/p4info.txt" "${tna_dir}/pipeline_config.pb.bin" "$dest_dir" 2>/dev/null && \
            echo "Copied TNA files from $tna_dir to $dest_dir" || \
            echo "Warning: Missing files in $tna_dir"

        # 重命名源目录（如果需要）
        new_tna_dir="${TNA_SRC_DIR}/tofino_${normalized_combo}"
        if [[ "$tna_dir" != "$new_tna_dir" ]]; then
            mv "$tna_dir" "$new_tna_dir"
            echo "Renamed $tna_dir to $new_tna_dir"
        fi
    fi
done

echo "All operations completed."