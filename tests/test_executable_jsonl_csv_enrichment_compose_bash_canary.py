"""Fixed reviewed Bash feasibility canary for JSONL/CSV enrichment.

Only the literal below is executed.  It is public method-development
feasibility evidence for one source-reviewed program, not a caller-selected
candidate API, production sandbox, scored evaluation, model-selection input,
or evidence about model quality.  Its restricted PATH demonstrates only that
this literal stays within the family's exact external-tool budget.  Final-state
verification does not prove physical intermediate materialization, tool
history, read scope, atomicity, transient behavior, candidate exit status, or
global quiescence.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cbds.executable_jsonl_csv_enrichment_compose as compose  # noqa: E402
from cbds.executable_fixture_profiles import (  # noqa: E402
    PUBLIC_DEVELOPMENT_FIXTURE_PROFILES,
)


_HAND_AUTHORED_BASH = r"""
set -euo pipefail

export LC_ALL=C
export TZ=UTC
umask 022
unset AWKLIBPATH AWKPATH JQ_COLORS POSIXLY_CORRECT

join_layout=${1:?join layout required}
missing_field_policy=${2:?missing-field policy required}
case $join_layout in
    jsonl-left-csv-right|csv-left-jsonl-right|jsonl-both-with-csv-output|csv-both-with-jsonl-output) ;;
    *) exit 64 ;;
esac
case $missing_field_policy in
    drop-row|empty-string|null-value|emit-reject-row|reject-source-file) ;;
    *) exit 65 ;;
esac

left_path=input/left.data
right_path=input/right.data
output_path=output/enriched.jsonl
separator=$'\x1f'

left_source_indexes=()
left_id_present=()
left_ids=()
left_value_present=()
left_values=()
right_source_indexes=()
right_id_present=()
right_ids=()
right_value_present=()
right_values=()

valid_text() {
    local value=$1
    [[ $value != *"$separator"* ]] || return 1
    [[ ! $value =~ [[:cntrl:]] ]] || return 1
}

append_source_row() {
    local side=$1
    local source_index=$2
    local has_identifier=$3
    local identifier=$4
    local has_value=$5
    local value=$6
    [[ $source_index =~ ^(0|[1-9][0-9]*)$ ]] || exit 66
    [[ $has_identifier == 0 || $has_identifier == 1 ]] || exit 66
    [[ $has_value == 0 || $has_value == 1 ]] || exit 66
    valid_text "$identifier" || exit 66
    valid_text "$value" || exit 66
    ((${#identifier} <= 128 && ${#value} <= 128)) || exit 66
    if [[ $has_identifier == 1 ]]; then
        [[ -n $identifier ]] || exit 66
    else
        [[ -z $identifier ]] || exit 66
    fi
    if [[ $has_value == 0 ]]; then
        [[ -z $value ]] || exit 66
    fi
    case $side in
        left)
            left_source_indexes+=("$source_index")
            left_id_present+=("$has_identifier")
            left_ids+=("$identifier")
            left_value_present+=("$has_value")
            left_values+=("$value")
            ;;
        right)
            right_source_indexes+=("$source_index")
            right_id_present+=("$has_identifier")
            right_ids+=("$identifier")
            right_value_present+=("$has_value")
            right_values+=("$value")
            ;;
        *)
            exit 66
            ;;
    esac
}

parse_jsonl() {
    local side=$1
    local source_path=$2
    local value_key
    local line
    local key_text
    local keys
    local key
    local seen_id
    local seen_value
    local value_text
    local values
    local source_index=0
    case $side in
        left) value_key=left ;;
        right) value_key=right ;;
        *) exit 66 ;;
    esac
    while :; do
        line=
        if IFS= read -r line; then
            [[ -n $line && $line != *$'\r'* ]] || exit 66
            key_text=$(
                jq --stream -r '
                    select(length == 2 and (.[0] | length) == 1)
                    | .[0][0]
                    | if type == "string"
                      then .
                      else error("non-string JSON member")
                      end
                ' <<< "$line"
            ) || exit 66
            keys=()
            mapfile -t keys < <(printf '%s' "$key_text")
            ((${#keys[@]} >= 1 && ${#keys[@]} <= 2)) || exit 66
            seen_id=0
            seen_value=0
            for key in "${keys[@]}"; do
                case $key in
                    id) ((seen_id += 1)) ;;
                    "$value_key") ((seen_value += 1)) ;;
                    *) exit 66 ;;
                esac
            done
            ((seen_id <= 1 && seen_value <= 1)) || exit 66
            value_text=$(
                jq -er --arg value_key "$value_key" --arg separator "$separator" '
                    if type == "object"
                       and (keys | length) >= 1
                       and ((keys - ["id", $value_key]) | length) == 0
                       and ((has("id") | not) or (.id | type) == "string")
                       and ((has($value_key) | not)
                            or (.[$value_key] | type) == "string")
                       and ((has("id") | not) or (.id | length) > 0)
                    then "entry" + $separator
                         + (if has("id") then "1" else "0" end)
                         + $separator + (if has("id") then .id else "" end)
                         + $separator
                         + (if has($value_key) then "1" else "0" end)
                         + $separator
                         + (if has($value_key) then .[$value_key] else "" end)
                         + $separator + "end"
                    else error("invalid enrichment record")
                    end
                ' <<< "$line"
            ) || exit 66
            values=()
            IFS=$separator read -r -a values <<< "$value_text"
            ((${#values[@]} == 6)) || exit 66
            [[ ${values[0]} == entry && ${values[5]} == end ]] || exit 66
            append_source_row \
                "$side" "$source_index" \
                "${values[1]}" "${values[2]}" "${values[3]}" "${values[4]}"
            ((source_index += 1))
        else
            [[ -z $line ]] || exit 66
            break
        fi
    done < "$source_path"
    ((source_index >= 1 && source_index <= 128)) || exit 66
}

validate_csv_crlf() {
    local source_path=$1
    local line
    while :; do
        line=
        if IFS= read -r line; then
            [[ $line == *$'\r' ]] || exit 66
        else
            [[ -z $line ]] || exit 66
            break
        fi
    done < "$source_path"
}

parse_csv() {
    local side=$1
    local source_path=$2
    local expected_header
    local rows
    local row
    local final
    local fields
    local has_identifier
    local has_value
    local source_index=0
    case $side in
        left) expected_header=id,left ;;
        right) expected_header=id,right ;;
        *) exit 66 ;;
    esac
    validate_csv_crlf "$source_path"
    rows=()
    mapfile -t rows < <(
        awk -v expected_header="$expected_header" -v separator="$separator" '
            function fail() {
                failed = 1
                exit 66
            }
            function parse_csv_record(line, fields,    after_quote, c, field, i, in_quote, n) {
                delete fields
                after_quote = 0
                field = ""
                in_quote = 0
                n = 1
                for (i = 1; i <= length(line); i += 1) {
                    c = substr(line, i, 1)
                    if (in_quote) {
                        if (c == "\"") {
                            if (substr(line, i + 1, 1) == "\"") {
                                field = field "\""
                                i += 1
                            } else {
                                in_quote = 0
                                after_quote = 1
                            }
                        } else {
                            field = field c
                        }
                    } else if (after_quote) {
                        if (c != ",") {
                            return 0
                        }
                        fields[n] = field
                        n += 1
                        field = ""
                        after_quote = 0
                    } else if (c == ",") {
                        fields[n] = field
                        n += 1
                        field = ""
                    } else if (c == "\"") {
                        if (length(field) != 0) {
                            return 0
                        }
                        in_quote = 1
                    } else {
                        field = field c
                    }
                }
                if (in_quote) {
                    return 0
                }
                fields[n] = field
                return n
            }
            {
                if (substr($0, length($0), 1) != "\r") {
                    fail()
                }
                line = substr($0, 1, length($0) - 1)
                if (NR == 1) {
                    if (line != expected_header) {
                        fail()
                    }
                    next
                }
                count = parse_csv_record(line, fields)
                if (count != 2) {
                    fail()
                }
                printf "entry%s%s%s%s%send\n", \
                    separator, fields[1], separator, fields[2], separator
                emitted += 1
            }
            END {
                if (!failed && NR > 0) {
                    printf "complete%s%d\n", separator, emitted
                }
            }
        ' "$source_path"
    )
    ((${#rows[@]} > 0)) || exit 66
    final=${rows[-1]}
    [[ $final == complete"$separator"* ]] || exit 66
    [[ ${final#*"$separator"} =~ ^(0|[1-9][0-9]*)$ ]] || exit 66
    ((${final#*"$separator"} == ${#rows[@]} - 1)) || exit 66
    for row in "${rows[@]:0:${#rows[@]}-1}"; do
        fields=()
        IFS=$separator read -r -a fields <<< "$row"
        ((${#fields[@]} == 4)) || exit 66
        [[ ${fields[0]} == entry && ${fields[3]} == end ]] || exit 66
        has_identifier=1
        has_value=1
        [[ -n ${fields[1]} ]] || has_identifier=0
        [[ -n ${fields[2]} ]] || has_value=0
        append_source_row \
            "$side" "$source_index" \
            "$has_identifier" "${fields[1]}" "$has_value" "${fields[2]}"
        ((source_index += 1))
    done
    ((source_index >= 1 && source_index <= 127)) || exit 66
}

case $join_layout in
    jsonl-left-csv-right)
        parse_jsonl left "$left_path"
        parse_csv right "$right_path"
        ;;
    csv-left-jsonl-right)
        parse_csv left "$left_path"
        parse_jsonl right "$right_path"
        ;;
    jsonl-both-with-csv-output)
        parse_jsonl left "$left_path"
        parse_jsonl right "$right_path"
        ;;
    csv-both-with-jsonl-output)
        parse_csv left "$left_path"
        parse_csv right "$right_path"
        ;;
esac
((${#left_ids[@]} == ${#left_values[@]}))
((${#left_ids[@]} == ${#left_id_present[@]}))
((${#left_ids[@]} == ${#left_value_present[@]}))
((${#left_ids[@]} == ${#left_source_indexes[@]}))
((${#right_ids[@]} == ${#right_values[@]}))
((${#right_ids[@]} == ${#right_id_present[@]}))
((${#right_ids[@]} == ${#right_value_present[@]}))
((${#right_ids[@]} == ${#right_source_indexes[@]}))

prepared_left_source_indexes=()
prepared_left_joinable=()
prepared_left_id_present=()
prepared_left_ids=()
prepared_left_value_present=()
prepared_left_values=()
prepared_right_source_indexes=()
prepared_right_joinable=()
prepared_right_id_present=()
prepared_right_ids=()
prepared_right_value_present=()
prepared_right_values=()

reject_sources=()
reject_source_indexes=()
reject_id_present=()
reject_ids=()
reject_missing_fields=()

source_reject_sources=()
source_reject_affected_counts=()
source_reject_missing_fields=()

enriched_id_present=()
enriched_ids=()
enriched_left_present=()
enriched_left_values=()
enriched_right_present=()
enriched_right_values=()
enriched_matched=()

append_prepared_left() {
    prepared_left_source_indexes+=("$1")
    prepared_left_joinable+=("$2")
    prepared_left_id_present+=("$3")
    prepared_left_ids+=("$4")
    prepared_left_value_present+=("$5")
    prepared_left_values+=("$6")
}

append_prepared_right() {
    prepared_right_source_indexes+=("$1")
    prepared_right_joinable+=("$2")
    prepared_right_id_present+=("$3")
    prepared_right_ids+=("$4")
    prepared_right_value_present+=("$5")
    prepared_right_values+=("$6")
}

append_reject() {
    reject_sources+=("$1")
    reject_source_indexes+=("$2")
    reject_id_present+=("$3")
    reject_ids+=("$4")
    reject_missing_fields+=("$5")
}

append_source_reject() {
    source_reject_sources+=("$1")
    source_reject_affected_counts+=("$2")
    source_reject_missing_fields+=("$3")
}

append_enriched() {
    enriched_id_present+=("$1")
    enriched_ids+=("$2")
    enriched_left_present+=("$3")
    enriched_left_values+=("$4")
    enriched_right_present+=("$5")
    enriched_right_values+=("$6")
    enriched_matched+=("$7")
}

left_invalid_count=0
left_missing_id=0
left_missing_value=0
for index in "${!left_ids[@]}"; do
    missing=
    if [[ ${left_id_present[index]} == 0 ]]; then
        missing=id
        left_missing_id=1
    fi
    if [[ ${left_value_present[index]} == 0 ]]; then
        missing+=${missing:+,}left
        left_missing_value=1
    fi
    if [[ -z $missing ]]; then
        append_prepared_left \
            "${left_source_indexes[index]}" 1 1 "${left_ids[index]}" \
            1 "${left_values[index]}"
        continue
    fi
    ((left_invalid_count += 1))
    case $missing_field_policy in
        drop-row|reject-source-file)
            ;;
        empty-string)
            append_prepared_left \
                "${left_source_indexes[index]}" \
                "${left_id_present[index]}" \
                1 "${left_ids[index]}" 1 "${left_values[index]}"
            ;;
        null-value)
            append_prepared_left \
                "${left_source_indexes[index]}" \
                "${left_id_present[index]}" \
                "${left_id_present[index]}" "${left_ids[index]}" \
                "${left_value_present[index]}" "${left_values[index]}"
            ;;
        emit-reject-row)
            append_reject \
                "$left_path" "${left_source_indexes[index]}" \
                "${left_id_present[index]}" "${left_ids[index]}" "$missing"
            ;;
    esac
done

right_invalid_count=0
right_missing_id=0
right_missing_value=0
for index in "${!right_ids[@]}"; do
    missing=
    if [[ ${right_id_present[index]} == 0 ]]; then
        missing=id
        right_missing_id=1
    fi
    if [[ ${right_value_present[index]} == 0 ]]; then
        missing+=${missing:+,}right
        right_missing_value=1
    fi
    if [[ -z $missing ]]; then
        append_prepared_right \
            "${right_source_indexes[index]}" 1 1 "${right_ids[index]}" \
            1 "${right_values[index]}"
        continue
    fi
    ((right_invalid_count += 1))
    case $missing_field_policy in
        drop-row|reject-source-file)
            ;;
        empty-string)
            append_prepared_right \
                "${right_source_indexes[index]}" \
                "${right_id_present[index]}" \
                1 "${right_ids[index]}" 1 "${right_values[index]}"
            ;;
        null-value)
            append_prepared_right \
                "${right_source_indexes[index]}" \
                "${right_id_present[index]}" \
                "${right_id_present[index]}" "${right_ids[index]}" \
                "${right_value_present[index]}" "${right_values[index]}"
            ;;
        emit-reject-row)
            append_reject \
                "$right_path" "${right_source_indexes[index]}" \
                "${right_id_present[index]}" "${right_ids[index]}" "$missing"
            ;;
    esac
done

perform_join() {
    local left_index
    local right_index
    local match_count
    for left_index in "${!prepared_left_ids[@]}"; do
        match_count=0
        if [[ ${prepared_left_joinable[left_index]} == 1 ]]; then
            for right_index in "${!prepared_right_ids[@]}"; do
                if [[
                    ${prepared_right_joinable[right_index]} == 1
                    && ${prepared_left_ids[left_index]} == "${prepared_right_ids[right_index]}"
                ]]; then
                    append_enriched \
                        "${prepared_left_id_present[left_index]}" \
                        "${prepared_left_ids[left_index]}" \
                        "${prepared_left_value_present[left_index]}" \
                        "${prepared_left_values[left_index]}" \
                        "${prepared_right_value_present[right_index]}" \
                        "${prepared_right_values[right_index]}" \
                        1
                    ((match_count += 1))
                fi
            done
        fi
        if ((match_count > 0)); then
            continue
        fi
        case $missing_field_policy in
            drop-row)
                ;;
            empty-string)
                append_enriched \
                    "${prepared_left_id_present[left_index]}" \
                    "${prepared_left_ids[left_index]}" \
                    "${prepared_left_value_present[left_index]}" \
                    "${prepared_left_values[left_index]}" \
                    1 "" 0
                ;;
            null-value)
                append_enriched \
                    "${prepared_left_id_present[left_index]}" \
                    "${prepared_left_ids[left_index]}" \
                    "${prepared_left_value_present[left_index]}" \
                    "${prepared_left_values[left_index]}" \
                    0 "" 0
                ;;
            emit-reject-row)
                append_reject \
                    join "${prepared_left_source_indexes[left_index]}" \
                    "${prepared_left_id_present[left_index]}" \
                    "${prepared_left_ids[left_index]}" right
                ;;
            reject-source-file)
                exit 66
                ;;
        esac
    done
}

if [[ $missing_field_policy == reject-source-file ]]; then
    unmatched_valid_left_count=0
    for left_index in "${!prepared_left_ids[@]}"; do
        matched=0
        for right_index in "${!prepared_right_ids[@]}"; do
            if [[
                ${prepared_left_ids[left_index]} == "${prepared_right_ids[right_index]}"
            ]]; then
                matched=1
                break
            fi
        done
        if [[ $matched == 0 ]]; then
            ((unmatched_valid_left_count += 1))
        fi
    done
    right_affected_count=$((right_invalid_count + unmatched_valid_left_count))
    if ((left_invalid_count > 0)); then
        missing=
        [[ $left_missing_id == 0 ]] || missing=id
        [[ $left_missing_value == 0 ]] || missing+=${missing:+,}left
        append_source_reject "$left_path" "$left_invalid_count" "$missing"
    fi
    if ((right_affected_count > 0)); then
        missing=
        [[ $right_missing_id == 0 ]] || missing=id
        if ((right_missing_value == 1 || unmatched_valid_left_count > 0)); then
            missing+=${missing:+,}right
        fi
        append_source_reject "$right_path" "$right_affected_count" "$missing"
    fi
    if ((${#source_reject_sources[@]} == 0)); then
        perform_join
    fi
else
    perform_join
fi

canonical_enriched_rows() {
    local index
    local line
    for index in "${!enriched_ids[@]}"; do
        line=$(
            jq -cn \
                --arg id "${enriched_ids[index]}" \
                --argjson id_present "${enriched_id_present[index]}" \
                --arg left "${enriched_left_values[index]}" \
                --argjson left_present "${enriched_left_present[index]}" \
                --argjson matched "${enriched_matched[index]}" \
                --arg right "${enriched_right_values[index]}" \
                --argjson right_present "${enriched_right_present[index]}" \
                '{
                    id: (if $id_present == 1 then $id else null end),
                    left: (if $left_present == 1 then $left else null end),
                    matched: ($matched == 1),
                    record: "enriched",
                    right: (if $right_present == 1 then $right else null end)
                }'
        ) || exit 66
        printf 'entry%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%send\n' \
            "$separator" "${enriched_id_present[index]}" \
            "$separator" "${enriched_ids[index]}" \
            "$separator" "${enriched_left_present[index]}" \
            "$separator" "${enriched_left_values[index]}" \
            "$separator" "${enriched_right_present[index]}" \
            "$separator" "${enriched_right_values[index]}" \
            "$separator" "${enriched_matched[index]}" \
            "$separator" "$line" "$separator"
    done |
        sort -t "$separator" \
            -k2,2n -k3,3 -k4,4n -k5,5 -k6,6n -k7,7 -k8,8n --
}

canonical_reject_rows() {
    local index
    local first_missing
    local second_missing
    local line
    for index in "${!reject_sources[@]}"; do
        first_missing=${reject_missing_fields[index]%%,*}
        if [[ ${reject_missing_fields[index]} == *,* ]]; then
            second_missing=${reject_missing_fields[index]#*,}
        else
            second_missing=
        fi
        line=$(
            jq -cn \
                --arg id "${reject_ids[index]}" \
                --argjson id_present "${reject_id_present[index]}" \
                --arg missing_a "$first_missing" \
                --arg missing_b "$second_missing" \
                --arg source "${reject_sources[index]}" \
                --argjson source_index "${reject_source_indexes[index]}" \
                '{
                    id: (if $id_present == 1 then $id else null end),
                    missing_fields: (
                        [$missing_a, $missing_b] | map(select(length > 0))
                    ),
                    record: "reject",
                    source: $source,
                    source_index: $source_index
                }'
        ) || exit 66
        printf 'entry%s%s%s%s%s%s%s%s%s%s%s%s%send\n' \
            "$separator" "${reject_sources[index]}" \
            "$separator" "${reject_source_indexes[index]}" \
            "$separator" "${reject_id_present[index]}" \
            "$separator" "${reject_ids[index]}" \
            "$separator" "${reject_missing_fields[index]}" \
            "$separator" "$line" "$separator"
    done |
        sort -t "$separator" \
            -k2,2 -k3,3n -k4,4n -k5,5 -k6,6 --
}

canonical_source_reject_rows() {
    local index
    local first_missing
    local second_missing
    local line
    for index in "${!source_reject_sources[@]}"; do
        first_missing=${source_reject_missing_fields[index]%%,*}
        if [[ ${source_reject_missing_fields[index]} == *,* ]]; then
            second_missing=${source_reject_missing_fields[index]#*,}
        else
            second_missing=
        fi
        line=$(
            jq -cn \
                --argjson affected_count "${source_reject_affected_counts[index]}" \
                --arg missing_a "$first_missing" \
                --arg missing_b "$second_missing" \
                --arg source "${source_reject_sources[index]}" \
                '{
                    affected_count: $affected_count,
                    missing_fields: (
                        [$missing_a, $missing_b] | map(select(length > 0))
                    ),
                    reason: "required-field-missing",
                    record: "source-reject",
                    source: $source
                }'
        ) || exit 66
        printf 'entry%s%s%s%s%send\n' \
            "$separator" "${source_reject_sources[index]}" \
            "$separator" "$line" "$separator"
    done |
        sort -t "$separator" -k2,2 --
}

sorted_enriched_rows=()
sorted_reject_rows=()
sorted_source_reject_rows=()
mapfile -t sorted_enriched_rows < <(canonical_enriched_rows)
mapfile -t sorted_reject_rows < <(canonical_reject_rows)
mapfile -t sorted_source_reject_rows < <(canonical_source_reject_rows)
((${#sorted_enriched_rows[@]} == ${#enriched_ids[@]}))
((${#sorted_reject_rows[@]} == ${#reject_sources[@]}))
((${#sorted_source_reject_rows[@]} == ${#source_reject_sources[@]}))

mkdir -p -- output
{
    jq -cn \
        --argjson enriched_count "${#enriched_ids[@]}" \
        --arg join_layout "$join_layout" \
        --arg missing_field_policy "$missing_field_policy" \
        --argjson reject_count "${#reject_sources[@]}" \
        --argjson source_reject_count "${#source_reject_sources[@]}" \
        '{
            enriched_count: $enriched_count,
            join_layout: $join_layout,
            missing_field_policy: $missing_field_policy,
            record: "compose",
            reject_count: $reject_count,
            source_reject_count: $source_reject_count
        }'
    for row in "${sorted_enriched_rows[@]}"; do
        fields=()
        IFS=$separator read -r -a fields <<< "$row"
        ((${#fields[@]} == 10)) || exit 66
        [[ ${fields[0]} == entry && ${fields[9]} == end ]] || exit 66
        printf '%s\n' "${fields[8]}"
    done
    for row in "${sorted_reject_rows[@]}"; do
        fields=()
        IFS=$separator read -r -a fields <<< "$row"
        ((${#fields[@]} == 8)) || exit 66
        [[ ${fields[0]} == entry && ${fields[7]} == end ]] || exit 66
        printf '%s\n' "${fields[6]}"
    done
    for row in "${sorted_source_reject_rows[@]}"; do
        fields=()
        IFS=$separator read -r -a fields <<< "$row"
        ((${#fields[@]} == 4)) || exit 66
        [[ ${fields[0]} == entry && ${fields[3]} == end ]] || exit 66
        printf '%s\n' "${fields[2]}"
    done
} > "$output_path"
""".lstrip()


_HAND_AUTHORED_BASH_SHA256 = (
    "d196400748ab440a429f49ab41fc7bda3858691a645d97d93d644aa15abc157f"
)
_HAND_AUTHORED_BASH_BYTE_COUNT = 24_966
_AGGREGATE_TEST_VECTOR_SHA256 = (
    "127db86d96da0d472915c5d2fc41d1fd34c2b316c4cf1c2ce244b14c7eb45a4e"
)
_UTF8_BOUNDARY_VECTOR_SHA256 = (
    "075de603daf44a6d0639a37668f677f00b8d9b98da6773b65209f1a1b9178901"
)
_CSV_FAILURE_VECTOR_SHA256 = (
    "8bbcac7fb76220085f7d3b314d046894276acd6106f6cc4fca4ea5a8c26fbe24"
)


def _binary_paths() -> tuple[str, dict[str, str]]:
    if os.name != "posix":
        raise RuntimeError(
            "the fixed JSONL/CSV enrichment Bash canary requires POSIX"
        )
    bash = shutil.which("bash")
    if bash is None or not os.access(bash, os.X_OK):
        raise RuntimeError("bash is unavailable or not executable")
    feature_probe = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            (
                "set -euo pipefail; "
                "values=(alpha beta); "
                "mapfile -t rows < <(printf '%s\\n' \"${values[@]}\"); "
                "[[ ${#rows[@]} == 2 && ${rows[1]} == beta ]]"
            ),
        ],
        env={"LANG": "C", "LC_ALL": "C", "PATH": "", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if feature_probe.returncode != 0:
        raise RuntimeError(
            "bash lacks the required strict-mode array/mapfile features"
        )
    if compose.JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS != (
        "awk",
        "jq",
        "mkdir",
        "sort",
    ):
        raise RuntimeError("family tool budget differs from the reviewed literal")
    tools: dict[str, str] = {}
    for name in compose.JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS:
        path = shutil.which(name)
        if path is None or not os.access(path, os.X_OK):
            raise RuntimeError(
                f"required canary tool {name!r} is unavailable or not executable"
            )
        tools[name] = path
    return bash, tools


def _write_fixed_canary(
    root: Path,
    tools: dict[str, str],
) -> tuple[Path, Path]:
    tool_root = root / "allowed-tools"
    tool_root.mkdir(mode=0o700)
    for name, target in tools.items():
        os.symlink(Path(target).resolve(), tool_root / name)
    script = root / "fixed-jsonl-csv-enrichment-compose-canary.bash"
    script.write_text(_HAND_AUTHORED_BASH, encoding="utf-8", newline="\n")
    script.chmod(0o400)
    return script, tool_root


def _run_fixed_canary(
    bash: str,
    script: Path,
    tool_root: Path,
    workspace: Path,
    join_layout: str,
    missing_field_policy: str,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            str(script),
            join_layout,
            missing_field_policy,
        ],
        cwd=workspace,
        env={
            "HOME": str(workspace),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": str(tool_root),
            "TZ": "UTC",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )


def _commit_piece(hasher: object, value: bytes) -> None:
    if type(value) is not bytes:
        raise TypeError("aggregate commitment pieces must be exact bytes")
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _run_all_materializations() -> str:
    bash, tools = _binary_paths()
    tasks = compose.build_jsonl_csv_enrichment_compose_tasks()
    if len(tasks) != 20 or len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES) != 5:
        raise RuntimeError("reviewed canary grid is not exactly 20 by 5")
    aggregate = sha256(b"cbds.fixed-jsonl-csv-enrichment-canary.v1\0")
    passed = 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        script, tool_root = _write_fixed_canary(root, tools)
        if {item.name for item in tool_root.iterdir()} != set(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS
        ):
            raise RuntimeError("restricted PATH does not exactly match tool budget")
        for task_index, task in enumerate(tasks):
            if (
                task.candidate_execution_authorized is not False
                or task.model_selection_eligible is not False
                or task.claim_authorized is not False
            ):
                raise RuntimeError("task unexpectedly grants research authority")
            for profile_index, profile in enumerate(
                PUBLIC_DEVELOPMENT_FIXTURE_PROFILES
            ):
                bundle = (
                    compose.build_jsonl_csv_enrichment_compose_fixture_bundle(
                        task,
                        profile,
                    )
                )
                workspace = (
                    root
                    / "workspaces"
                    / f"{task_index:02d}-{profile_index}"
                )
                with compose.materialize_jsonl_csv_enrichment_compose_fixture(
                    task,
                    profile,
                    bundle,
                    workspace,
                ) as handle:
                    completed = _run_fixed_canary(
                        bash,
                        script,
                        tool_root,
                        workspace,
                        task.parameters.join_layout,
                        task.parameters.missing_field_policy,
                    )
                    if (
                        completed.returncode != 0
                        or completed.stdout
                        or completed.stderr
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed: "
                            + (completed.stdout + completed.stderr).decode(
                                "utf-8", errors="replace"
                            )
                        )
                    if not compose.verify_jsonl_csv_enrichment_compose_workspace(
                        task,
                        profile,
                        bundle,
                        handle,
                    ):
                        raise RuntimeError(
                            "reviewed Bash literal failed trusted verification"
                        )
                    output_scan = handle.scan_outputs()
                    observed = handle.read_output_bytes(
                        output_scan,
                        compose.JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT,
                    )
                    if observed != bundle.oracle.state.output:
                        raise RuntimeError(
                            "reviewed Bash literal is not byte-canonical"
                        )
                    for piece in (
                        task.task_id.encode("ascii"),
                        profile.profile_id.encode("ascii"),
                        bundle.definition.fixture_id.encode("ascii"),
                        bundle.definition.fixture_sha256.encode("ascii"),
                        observed,
                    ):
                        _commit_piece(aggregate, piece)
                    if (
                        bundle.candidate_execution_authorized is not False
                        or bundle.model_selection_eligible is not False
                        or bundle.claim_authorized is not False
                    ):
                        raise RuntimeError(
                            "fixture unexpectedly grants research authority"
                        )
                    passed += 1
    if passed != 100:
        raise RuntimeError("reviewed Bash literal did not cover 100 bundles")
    return aggregate.hexdigest()


class JsonlCsvEnrichmentComposeBashCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = compose.build_jsonl_csv_enrichment_compose_tasks()

    def test_fixed_literal_solves_all_twenty_cells_and_five_profiles(
        self,
    ) -> None:
        self.assertEqual(
            _run_all_materializations(),
            _AGGREGATE_TEST_VECTOR_SHA256,
        )

    def test_all_materializations_survive_opposite_optimization(self) -> None:
        _binary_paths()
        opposite = ("-O",) if sys.flags.optimize == 0 else ()
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT), str(ROOT / "src"))
        )
        script = (
            "from tests."
            "test_executable_jsonl_csv_enrichment_compose_bash_canary "
            "import _AGGREGATE_TEST_VECTOR_SHA256, _run_all_materializations; "
            "observed = _run_all_materializations(); "
            "raise SystemExit("
            "0 if observed == _AGGREGATE_TEST_VECTOR_SHA256 else 1)"
        )
        completed = subprocess.run(
            [sys.executable, *opposite, "-c", script],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=360,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_utf8_byte_boundary_and_csv_parser_failure_fail_closed(self) -> None:
        bash, tools = _binary_paths()
        boundary_value = ("雪" * 42) + "ab"
        oversized_value = boundary_value + "b"
        self.assertEqual(len(boundary_value.encode("utf-8")), 128)
        self.assertEqual(len(oversized_value.encode("utf-8")), 129)
        valid_left = (
            '{"id":"key","left":"' + boundary_value + '"}\n'
        ).encode("utf-8")
        oversized_left = (
            '{"id":"key","left":"' + oversized_value + '"}\n'
        ).encode("utf-8")
        valid_right = b'id,right\r\nkey,"quoted, ""right"""\r\n'
        malformed_after_valid = (
            b'id,left\r\n'
            b'key,already-emitted\r\n'
            b'"unterminated,value\r\n'
        )
        vector = sha256(b"cbds.enrichment-utf8-boundary-vector.v1\0")
        for piece in (valid_left, oversized_left, valid_right):
            _commit_piece(vector, piece)
        self.assertEqual(vector.hexdigest(), _UTF8_BOUNDARY_VECTOR_SHA256)
        failure_vector = sha256(b"cbds.enrichment-csv-failure-vector.v1\0")
        for piece in (malformed_after_valid, valid_right):
            _commit_piece(failure_vector, piece)
        self.assertEqual(failure_vector.hexdigest(), _CSV_FAILURE_VECTOR_SHA256)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script, tool_root = _write_fixed_canary(root, tools)

            valid_workspace = root / "valid"
            (valid_workspace / "input").mkdir(parents=True)
            (valid_workspace / "input" / "left.data").write_bytes(valid_left)
            (valid_workspace / "input" / "right.data").write_bytes(valid_right)
            valid = _run_fixed_canary(
                bash,
                script,
                tool_root,
                valid_workspace,
                "jsonl-left-csv-right",
                "drop-row",
            )
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            self.assertEqual(valid.stdout, b"")
            self.assertEqual(valid.stderr, b"")
            self.assertTrue(
                (valid_workspace / "output" / "enriched.jsonl").is_file()
            )

            oversized_workspace = root / "oversized"
            (oversized_workspace / "input").mkdir(parents=True)
            (oversized_workspace / "input" / "left.data").write_bytes(
                oversized_left
            )
            (oversized_workspace / "input" / "right.data").write_bytes(
                valid_right
            )
            oversized = _run_fixed_canary(
                bash,
                script,
                tool_root,
                oversized_workspace,
                "jsonl-left-csv-right",
                "drop-row",
            )
            self.assertNotEqual(oversized.returncode, 0)
            self.assertFalse((oversized_workspace / "output").exists())

            malformed_workspace = root / "malformed"
            (malformed_workspace / "input").mkdir(parents=True)
            (malformed_workspace / "input" / "left.data").write_bytes(
                malformed_after_valid
            )
            (malformed_workspace / "input" / "right.data").write_bytes(
                valid_right
            )
            malformed = _run_fixed_canary(
                bash,
                script,
                tool_root,
                malformed_workspace,
                "csv-both-with-jsonl-output",
                "drop-row",
            )
            self.assertNotEqual(malformed.returncode, 0)
            self.assertFalse((malformed_workspace / "output").exists())

    def test_literal_hash_tool_budget_vectors_and_nonclaim_boundary(self) -> None:
        self.assertEqual(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_ALLOWED_TOOLS,
            ("awk", "jq", "mkdir", "sort"),
        )
        self.assertEqual(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_JOIN_LAYOUTS,
            (
                "jsonl-left-csv-right",
                "csv-left-jsonl-right",
                "jsonl-both-with-csv-output",
                "csv-both-with-jsonl-output",
            ),
        )
        self.assertEqual(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_MISSING_FIELD_POLICIES,
            (
                "drop-row",
                "empty-string",
                "null-value",
                "emit-reject-row",
                "reject-source-file",
            ),
        )
        self.assertEqual(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_OUTPUT,
            "output/enriched.jsonl",
        )
        self.assertEqual(len(self.tasks), 20)
        self.assertEqual(len(PUBLIC_DEVELOPMENT_FIXTURE_PROFILES), 5)
        self.assertTrue(
            all(
                task.candidate_execution_authorized is False
                and task.model_selection_eligible is False
                and task.claim_authorized is False
                for task in self.tasks
            )
        )
        for profile in PUBLIC_DEVELOPMENT_FIXTURE_PROFILES:
            self.assertIs(profile.candidate_execution_authorized, False)
            self.assertIs(profile.model_selection_eligible, False)
            self.assertIs(profile.claim_authorized, False)

        self.assertIs(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_FINAL_OUTPUT_OBSERVED,
            True,
        )
        self.assertIs(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_INPUT_PRESERVATION_OBSERVED,
            True,
        )
        self.assertIs(
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_VERIFIER_REQUIRES_TRUSTED_QUIESCENCE,
            True,
        )
        for boundary in (
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_INTERMEDIATE_MATERIALIZATION_OBSERVED,
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_ATOMICITY_OBSERVED,
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_TOOL_HISTORY_OBSERVED,
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_READ_SCOPE_OBSERVED,
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_CANDIDATE_EXIT_STATUS_OBSERVED,
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_TRANSIENT_STATE_OBSERVED,
            compose.JSONL_CSV_ENRICHMENT_COMPOSE_WORKSPACE_SCANS_PROVE_GLOBAL_QUIESCENCE,
        ):
            self.assertIs(boundary, False)

        self.assertNotIn("/usr/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("/bin/", _HAND_AUTHORED_BASH)
        self.assertNotIn("python", _HAND_AUTHORED_BASH.lower())
        self.assertNotIn("perl", _HAND_AUTHORED_BASH.lower())
        for forbidden in (
            " cat ",
            " cp ",
            " find ",
            " grep ",
            " mv ",
            " rm ",
            " sed ",
            " stat ",
            " tr ",
        ):
            self.assertNotIn(forbidden, f" {_HAND_AUTHORED_BASH} ")
        self.assertIn("awk -v", _HAND_AUTHORED_BASH)
        self.assertIn("jq --stream", _HAND_AUTHORED_BASH)
        self.assertIn("mkdir -p --", _HAND_AUTHORED_BASH)
        self.assertIn('sort -t "$separator"', _HAND_AUTHORED_BASH)
        self.assertEqual(
            sha256(_HAND_AUTHORED_BASH.encode("utf-8")).hexdigest(),
            _HAND_AUTHORED_BASH_SHA256,
        )
        self.assertEqual(
            len(_HAND_AUTHORED_BASH.encode("utf-8")),
            _HAND_AUTHORED_BASH_BYTE_COUNT,
        )
        self.assertRegex(_AGGREGATE_TEST_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(_UTF8_BOUNDARY_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")
        self.assertRegex(_CSV_FAILURE_VECTOR_SHA256, r"\A[0-9a-f]{64}\Z")


if __name__ == "__main__":
    unittest.main()
