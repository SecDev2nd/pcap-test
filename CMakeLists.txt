cmake_minimum_required(VERSION 3.0)
project(pcap-test)

# pcap 라이브러리 찾기
find_library(PCAP_LIBRARY pcap)

# 실행 파일 생성
add_executable(pcap-test src/pcap-test.c)

# pcap 라이브러리 링크
target_link_libraries(pcap-test ${PCAP_LIBRARY})
