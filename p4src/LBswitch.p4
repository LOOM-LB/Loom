/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define HASH_CONST 4
#define HASH_CONST_BIT 5
#define MAX_DIP_BIT 4
#define MAX_DIP_NUM 16
#define VER_BIT 6
#define MAX_ROUTE_NUM 2048

#define MAX_BLM 1024
#define MAX_BLM_BIT 10

#define CONTROLLER_SESSION_ID 250
#define SPECIAL_SRC_MAC 723

#define HOST_PORT 0
#define SERVER_MAC 255


header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

#define IP_PROT_TCP 0x06

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(m_metadata.tcpLength, ipv4.totalLen - 20);
    return select(ipv4.protocol) {
        IP_PROT_TCP : parse_tcp;
        default : ingress;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags1 : 6;
        syn: 1;
        flags2 : 1;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        m_metadata.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags1;
        tcp.syn;
        tcp.flags2;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}

action _drop() {
    drop();
}

header_type custom_metadata_t {
    fields {
        num: MAX_DIP_BIT;
        mod: HASH_CONST_BIT;
        mac: 48;
        ip: 32;
        version: 2;
        port: MAX_DIP_BIT;
        tcpLength: 16;
        hash1: MAX_BLM_BIT;
        base_hash: MAX_BLM_BIT;
        hash2: MAX_BLM_BIT;
        hash3: MAX_BLM_BIT;
        hash4: MAX_BLM_BIT;
        hash5: MAX_BLM_BIT;
        bloomidx: 1;
        checkflag: 1;
        checkbit1: 1;
        checkbit2: 1;
        checkbit3: 1;
        checkbit4: 1;
        checkbit5: 1;
    }
}

metadata custom_metadata_t m_metadata;

field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation crc_hash_cal {
    input { 
        hash_fields;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation csum_hash_cal {
    input { 
        hash_fields;
    }
    algorithm : csum16;
    output_width : 16;
}

register bloom_filter0{
    width : 1;
    instance_count : MAX_BLM ; 
}

register bloom_filter1{
    width : 1;
    instance_count : MAX_BLM ; 
}

register bloom_state{
    width : 1;
    instance_count : 1; 
}

register version_reg{
    width : 2;
    instance_count : 2;
}

action select_dip(dip_num) {
    modify_field(m_metadata.num, dip_num);
}

action hash_action(){
    modify_field_with_hash_based_offset(m_metadata.mod, 0,crc_hash_cal, HASH_CONST);
    modify_field_with_hash_based_offset(m_metadata.hash1, 0, crc_hash_cal, MAX_BLM);
    modify_field_with_hash_based_offset(m_metadata.base_hash, 0, csum_hash_cal, MAX_BLM);
    add(m_metadata.hash2,m_metadata.hash1,m_metadata.base_hash);
    add(m_metadata.hash3,m_metadata.hash2,m_metadata.base_hash);
    add(m_metadata.hash4,m_metadata.hash3,m_metadata.base_hash);
    add(m_metadata.hash5,m_metadata.hash4,m_metadata.base_hash);
    register_read(m_metadata.bloomidx, bloom_state, 0);
}

action checkbloom0(){
    register_read(m_metadata.checkbit1, bloom_filter0, m_metadata.hash1);
    register_read(m_metadata.checkbit2, bloom_filter0, m_metadata.hash2);
    register_read(m_metadata.checkbit3, bloom_filter0, m_metadata.hash3);
    register_read(m_metadata.checkbit4, bloom_filter0, m_metadata.hash4);
    register_read(m_metadata.checkbit5, bloom_filter0, m_metadata.hash5);
    modify_field(m_metadata.checkflag,m_metadata.checkbit1);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit2);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit3);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit4);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit5);
    register_read(m_metadata.version,version_reg,m_metadata.checkflag);
}

action checkbloom1(){
    register_read(m_metadata.checkbit1, bloom_filter1, m_metadata.hash1);
    register_read(m_metadata.checkbit2, bloom_filter1, m_metadata.hash2);
    register_read(m_metadata.checkbit3, bloom_filter1, m_metadata.hash3);
    register_read(m_metadata.checkbit4, bloom_filter1, m_metadata.hash4);
    register_read(m_metadata.checkbit5, bloom_filter1, m_metadata.hash5);
    modify_field(m_metadata.checkflag,m_metadata.checkbit1);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit2);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit3);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit4);
    bit_and(m_metadata.checkflag,m_metadata.checkflag,m_metadata.checkbit5);
    register_read(m_metadata.version,version_reg,m_metadata.checkflag);
}

action writebloom0(){
    register_write(bloom_filter0, m_metadata.hash1, 1);
    register_write(bloom_filter0, m_metadata.hash2, 1);
    register_write(bloom_filter0, m_metadata.hash3, 1);
    register_write(bloom_filter0, m_metadata.hash4, 1);
    register_write(bloom_filter0, m_metadata.hash5, 1);
}

action writebloom1(){
    register_write(bloom_filter1, m_metadata.hash1, 1);
    register_write(bloom_filter1, m_metadata.hash2, 1);
    register_write(bloom_filter1, m_metadata.hash3, 1);
    register_write(bloom_filter1, m_metadata.hash4, 1);
    register_write(bloom_filter1, m_metadata.hash5, 1);
}

action push_to_controller(port){
    modify_field(standard_metadata.egress_spec, port);
    modify_field(m_metadata.num, 15);
}

action map_dip(ip, mac, port){
    modify_field(ipv4.dstAddr, ip);
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ethernet.dstAddr, mac);
    subtract_from_field(ipv4.ttl, 1);
}

action inverse_nat(vip){
    modify_field(ipv4.srcAddr,vip);
    modify_field(ethernet.srcAddr,SERVER_MAC);
    modify_field(standard_metadata.egress_spec, HOST_PORT);
}

action conn_action(num){
    modify_field(m_metadata.num, num);
}

// TODO: Define the tables to run actions
table innat_table {
    reads {
        ipv4.srcAddr : exact;
    }
    actions {
        inverse_nat;
    }
    size : MAX_DIP_NUM;
}

table conn_table {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
        ipv4.protocol : exact;
        tcp.srcPort : exact;
        tcp.dstPort : exact;
    }
    actions {
        conn_action;
    }
    size : 65536;
}

table hash_table{
    actions {
        hash_action;
    }
    size: 1;
}

table checkbloom_table{
    reads {
        m_metadata.bloomidx : exact;
    }
    actions {
        checkbloom0;
        checkbloom1;
    }
    size: 2;
}

table syn_table {
    reads {
        m_metadata.checkflag : exact;
        tcp.syn: exact;
    }
    actions {
        push_to_controller;
    }
    size: 1;
}

table route_table {
    reads {
        m_metadata.mod : exact;
        m_metadata.version : exact;
    }
    actions {
        select_dip;
    }
    size: MAX_ROUTE_NUM;
}

table writebloom_table{
    reads {
        m_metadata.bloomidx : exact;
        m_metadata.checkflag : exact;
    }
    actions {
        writebloom0;
        writebloom1;
    }
    size: 2;
}

table map_table {
    reads {
        m_metadata.num : exact;
    }
    actions {
        map_dip;
    }
    size: MAX_DIP_NUM;
}

control ingress {
    apply(innat_table){
        miss{
            apply(conn_table){
                miss{
                    apply(hash_table);
                    apply(checkbloom_table);
                    apply(syn_table){
                        miss{
                            apply(route_table);
                            apply(writebloom_table);
                        }
                    }
                }
            }
            apply(map_table);
        }
    }
}


control egress {
}
