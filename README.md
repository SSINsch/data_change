————————————————————————————————————
Data Change using WINDIVERT
============
### 필요 스킬  
  1. data parsing
    + 들어오는 패킷의 IP header, TCP header, TCP data 위치를 알아낸다.
    + TCP data 내의 encoding에서 gzip을 제거하여 전체 패킷을 볼 수 있게 변경한다.
    + TCP data 내의 특정 문자열을 발견하면 이를 다른 것으로 대체한다. (이 때, 글자 길이는 유지)


  1. TCP checksum  
    다음의 데이터들을 모두 계산한다. 계산에 있어서 자리올림이 생기면 wraparound를 적용
    
    + TCP header 밑의 data 
    + src IP, dst IP 
    + pseudo TCP header: protocol, TCP 전체 길이 (header + data) 

    
+ 덤으로 프로젝트 속성 변경은 screenshot 폴더에 정리되어있다.  

===========