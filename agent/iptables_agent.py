#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redis IPTables Agent
Redis Pub/Sub을 구독하여 실시간으로 iptables 규칙을 적용하는 에이전트
root 권한으로 실행 필요
"""

import redis
import subprocess
import json
import logging
import sys
import signal
import time
from datetime import datetime

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/iptables_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Redis 설정
REDIS_HOST = '42.125.244.4'
REDIS_PORT = 6379
REDIS_PASS = 'K9mX#vL8@pN2$qR5*wT7&uY1!zA4^bE6+cF3%dG9-hJ0~iM8'
REDIS_DB = 0
REDIS_CHANNEL = 'fw:events'

class IPTablesAgent:
    def __init__(self):
        self.redis_client = None
        self.pubsub = None
        self.running = True
        
    def connect_redis(self):
        """Redis 연결"""
        try:
            self.redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASS,
                db=REDIS_DB,
                decode_responses=True
            )
            self.pubsub = self.redis_client.pubsub()
            self.pubsub.subscribe(REDIS_CHANNEL)
            logger.info(f"Redis 연결 성공: {REDIS_HOST}:{REDIS_PORT}")
            return True
        except Exception as e:
            logger.error(f"Redis 연결 실패: {e}")
            return False
    
    def execute_iptables(self, cmd):
        """iptables 명령 실행"""
        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"명령 성공: {' '.join(cmd)}")
                return True
            else:
                # 이미 존재하는 규칙 삭제 시도 등의 경우 무시
                if "No chain/target/match" in result.stderr or "does not exist" in result.stderr:
                    logger.warning(f"규칙이 존재하지 않음: {' '.join(cmd)}")
                    return True
                logger.error(f"명령 실패: {' '.join(cmd)} - {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"명령 타임아웃: {' '.join(cmd)}")
            return False
        except Exception as e:
            logger.error(f"명령 실행 오류: {' '.join(cmd)} - {e}")
            return False
    
    def handle_message(self, message):
        """Redis 메시지 처리"""
        try:
            if message['type'] != 'message':
                return
            
            data = message['data']
            logger.info(f"메시지 수신: {data}")
            
            # 메시지 파싱 (형식: "action target")
            parts = data.split(' ', 1)
            if len(parts) != 2:
                logger.warning(f"잘못된 메시지 형식: {data}")
                return
            
            action, target = parts
            
            # IP 차단/해제
            if action == 'ban_ip':
                self.execute_iptables(['iptables', '-A', 'INPUT', '-s', target, '-j', 'DROP'])
                self.execute_iptables(['iptables', '-A', 'OUTPUT', '-d', target, '-j', 'DROP'])
                
            elif action == 'unban_ip':
                self.execute_iptables(['iptables', '-D', 'INPUT', '-s', target, '-j', 'DROP'])
                self.execute_iptables(['iptables', '-D', 'OUTPUT', '-d', target, '-j', 'DROP'])
            
            # 포트 차단/해제
            elif action == 'block_port':
                port = target
                self.execute_iptables(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP'])
                self.execute_iptables(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', port, '-j', 'DROP'])
                
            elif action == 'unblock_port':
                port = target
                self.execute_iptables(['iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP'])
                self.execute_iptables(['iptables', '-D', 'INPUT', '-p', 'udp', '--dport', port, '-j', 'DROP'])
            
            # IP+포트 조합 처리
            elif action in ['block_ipport', 'unblock_ipport', 'allow_ipport', 'unallow_ipport']:
                # target 형식: "192.168.1.100:8080" 또는 "192.168.1.100:8080:tcp"
                parts = target.split(':')
                if len(parts) < 2:
                    logger.warning(f"잘못된 IP:포트 형식: {target}")
                    return
                
                ip = parts[0]
                port = parts[1]
                protocol = parts[2] if len(parts) > 2 else 'tcp'
                
                if action == 'block_ipport':
                    self.execute_iptables(['iptables', '-A', 'INPUT', '-s', ip, '-p', protocol, '--dport', port, '-j', 'DROP'])
                    
                elif action == 'unblock_ipport':
                    self.execute_iptables(['iptables', '-D', 'INPUT', '-s', ip, '-p', protocol, '--dport', port, '-j', 'DROP'])
                    
                elif action == 'allow_ipport':
                    # ACCEPT 규칙을 DROP 규칙보다 앞에 추가
                    self.execute_iptables(['iptables', '-I', 'INPUT', '-s', ip, '-p', protocol, '--dport', port, '-j', 'ACCEPT'])
                    
                elif action == 'unallow_ipport':
                    self.execute_iptables(['iptables', '-D', 'INPUT', '-s', ip, '-p', protocol, '--dport', port, '-j', 'ACCEPT'])
            
            else:
                logger.warning(f"알 수 없는 액션: {action}")
                
        except Exception as e:
            logger.error(f"메시지 처리 오류: {e}")
    
    def sync_rules_from_redis(self):
        """Redis에서 현재 규칙을 읽어 iptables에 동기화"""
        try:
            logger.info("Redis 규칙 동기화 시작...")
            
            # 차단된 IP 목록
            banned_ips = self.redis_client.smembers('fw:blacklist:ips')
            for ip in banned_ips:
                self.execute_iptables(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                self.execute_iptables(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'])
            
            # 차단된 포트 목록
            blocked_ports = self.redis_client.smembers('fw:blacklist:ports')
            for port in blocked_ports:
                self.execute_iptables(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'DROP'])
                self.execute_iptables(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', port, '-j', 'DROP'])
            
            # 차단된 IP:포트 조합
            blocked_ipports = self.redis_client.smembers('fw:blacklist:ip_ports')
            for ipport in blocked_ipports:
                parts = ipport.split(':')
                if len(parts) >= 2:
                    ip, port = parts[0], parts[1]
                    protocol = parts[2] if len(parts) > 2 else 'tcp'
                    self.execute_iptables(['iptables', '-A', 'INPUT', '-s', ip, '-p', protocol, '--dport', port, '-j', 'DROP'])
            
            # 허용된 IP:포트 조합 (ACCEPT 규칙)
            allowed_ipports = self.redis_client.smembers('fw:whitelist:ip_ports')
            for ipport in allowed_ipports:
                parts = ipport.split(':')
                if len(parts) >= 2:
                    ip, port = parts[0], parts[1]
                    protocol = parts[2] if len(parts) > 2 else 'tcp'
                    self.execute_iptables(['iptables', '-I', 'INPUT', '-s', ip, '-p', protocol, '--dport', port, '-j', 'ACCEPT'])
            
            logger.info("Redis 규칙 동기화 완료")
            
        except Exception as e:
            logger.error(f"규칙 동기화 실패: {e}")
    
    def run(self):
        """메인 실행 루프"""
        # Redis 연결
        retry_count = 0
        while not self.connect_redis() and retry_count < 5:
            retry_count += 1
            logger.info(f"재연결 시도 {retry_count}/5...")
            time.sleep(5)
        
        if not self.redis_client:
            logger.error("Redis 연결 실패. 종료합니다.")
            return
        
        # 시작 시 기존 규칙 동기화
        self.sync_rules_from_redis()
        
        # 메시지 구독 루프
        logger.info("메시지 구독 시작...")
        while self.running:
            try:
                for message in self.pubsub.listen():
                    if not self.running:
                        break
                    self.handle_message(message)
                    
            except redis.ConnectionError:
                logger.error("Redis 연결 끊김. 재연결 시도...")
                time.sleep(5)
                if self.connect_redis():
                    self.sync_rules_from_redis()
                    
            except KeyboardInterrupt:
                break
                
            except Exception as e:
                logger.error(f"예상치 못한 오류: {e}")
                time.sleep(5)
        
        logger.info("에이전트 종료")
    
    def stop(self):
        """에이전트 중지"""
        self.running = False
        if self.pubsub:
            self.pubsub.close()
        if self.redis_client:
            self.redis_client.close()

def signal_handler(signum, frame):
    """시그널 핸들러"""
    logger.info(f"시그널 {signum} 수신. 종료합니다.")
    if agent:
        agent.stop()
    sys.exit(0)

if __name__ == '__main__':
    # root 권한 체크
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        logger.error("이 스크립트는 root 권한으로 실행해야 합니다.")
        sys.exit(1)
    
    # 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 에이전트 실행
    agent = IPTablesAgent()
    agent.run()