#!/usr/bin/env python3
"""
Paste-Site Leaks Monitor
Monitors public paste sites for potential credential leaks and data breaches.
Demonstrates OSINT, data leak monitoring, and automated threat intelligence gathering.
"""

import re
import time
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Set
import requests
from bs4 import BeautifulSoup

class PasteMonitor:
    def __init__(self, discord_webhook: str = None, telegram_bot_token: str = None, telegram_chat_id: str = None):
        """
        Initialize the Paste Site Monitor
        
        Args:
            discord_webhook: Discord webhook URL for alerts
            telegram_bot_token: Telegram bot token for alerts
            telegram_chat_id: Telegram chat ID for alerts
        """
        self.discord_webhook = discord_webhook
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        
        
        self.seen_hashes: Set[str] = set()
        
        self.keywords = [
            'password', 'passwords', 'combo', 'combos', 'database', 'leak',
            'breach', 'hacked', 'dump', 'sql', 'credentials', 'leaked',
            '@gmail.com', '@yahoo.com', '@outlook.com', 'username:password',
            'email:pass', 'login:', 'account:', 'cracked'
        ]
        
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def hash_content(self, content: str) -> str:
        """Create hash of content to track duplicates"""
        return hashlib.md5(content.encode()).hexdigest()
    
    def analyze_paste(self, content: str) -> Dict:
        """
        Analyze paste content for suspicious patterns
        
        Returns:
            Dict with threat score and detected patterns
        """
        content_lower = content.lower()
        
        found_keywords = [kw for kw in self.keywords if kw in content_lower]
        
        emails = self.email_pattern.findall(content)
        
      
        password_patterns = len(re.findall(r'\S+:\S+', content))
  
        threat_score = 0
        threat_score += len(found_keywords) * 10
        threat_score += min(len(emails), 10) * 5
        threat_score += min(password_patterns, 20) * 3
        
        return {
            'threat_score': threat_score,
            'keywords_found': found_keywords,
            'email_count': len(emails),
            'sample_emails': emails[:5] if emails else [],
            'credential_patterns': password_patterns
        }
    
    def scrape_pastebin_recent(self) -> List[Dict]:
        """
        Scrape recent Pastebin posts (archive page)
        Note: Pastebin may require API key for full access
        """
        results = []
        
        try:
          
            url = 'https://pastebin.com/archive'
            response = self.session.get(url, timeout=10)
            
            if response.status_code != 200:
                print(f"[!] Failed to fetch Pastebin archive: {response.status_code}")
                return results
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
          
            paste_links = soup.find_all('a', href=re.compile(r'^/\w{8}$'))
            
            for link in paste_links[:10]:  
                paste_id = link['href'][1:]
                paste_url = f'https://pastebin.com/raw/{paste_id}'
                
                try:
                    paste_response = self.session.get(paste_url, timeout=10)
                    
                    if paste_response.status_code == 200:
                        content = paste_response.text
                        content_hash = self.hash_content(content)
                        
                       
                        if content_hash in self.seen_hashes:
                            continue
                        
                        self.seen_hashes.add(content_hash)
                        
                        
                        analysis = self.analyze_paste(content)
                        
                        if analysis['threat_score'] > 30:
                            results.append({
                                'source': 'Pastebin',
                                'url': f'https://pastebin.com/{paste_id}',
                                'content_preview': content[:500],
                                'analysis': analysis,
                                'timestamp': datetime.now().isoformat()
                            })
                    
                    time.sleep(1) 
                
                except Exception as e:
                    print(f"[!] Error fetching paste {paste_id}: {e}")
                    continue
        
        except Exception as e:
            print(f"[!] Error scraping Pastebin: {e}")
        
        return results
    
    def scrape_ghostbin(self) -> List[Dict]:
        """Scrape GhostBin recent pastes"""
        results = []
        
        try:
            url = 'https://ghostbin.com/browse'
            response = self.session.get(url, timeout=10)
            
            if response.status_code != 200:
                return results
            
            soup = BeautifulSoup(response.text, 'html.parser')
            paste_links = soup.find_all('a', href=re.compile(r'^/paste/\w+$'))
            
            for link in paste_links[:5]:
                paste_url = f"https://ghostbin.com{link['href']}/raw"
                
                try:
                    paste_response = self.session.get(paste_url, timeout=10)
                    
                    if paste_response.status_code == 200:
                        content = paste_response.text
                        content_hash = self.hash_content(content)
                        
                        if content_hash in self.seen_hashes:
                            continue
                        
                        self.seen_hashes.add(content_hash)
                        analysis = self.analyze_paste(content)
                        
                        if analysis['threat_score'] > 30:
                            results.append({
                                'source': 'GhostBin',
                                'url': paste_url.replace('/raw', ''),
                                'content_preview': content[:500],
                                'analysis': analysis,
                                'timestamp': datetime.now().isoformat()
                            })
                    
                    time.sleep(1)
                
                except Exception as e:
                    print(f"[!] Error fetching GhostBin paste: {e}")
                    continue
        
        except Exception as e:
            print(f"[!] Error scraping GhostBin: {e}")
        
        return results
    
    def send_discord_alert(self, leak_data: Dict):
        """Send alert to Discord webhook"""
        if not self.discord_webhook:
            return
        
        try:
            embed = {
                "embeds": [{
                    "title": "🚨 Potential Data Leak Detected",
                    "color": 15158332,  # Red
                    "fields": [
                        {"name": "Source", "value": leak_data['source'], "inline": True},
                        {"name": "Threat Score", "value": str(leak_data['analysis']['threat_score']), "inline": True},
                        {"name": "URL", "value": leak_data['url'], "inline": False},
                        {"name": "Keywords Found", "value": ", ".join(leak_data['analysis']['keywords_found'][:5]), "inline": False},
                        {"name": "Emails Found", "value": str(leak_data['analysis']['email_count']), "inline": True},
                        {"name": "Credential Patterns", "value": str(leak_data['analysis']['credential_patterns']), "inline": True},
                        {"name": "Preview", "value": f"```{leak_data['content_preview'][:200]}...```", "inline": False}
                    ],
                    "timestamp": leak_data['timestamp']
                }]
            }
            
            response = requests.post(self.discord_webhook, json=embed, timeout=10)
            
            if response.status_code == 204:
                print("[✓] Discord alert sent successfully")
            else:
                print(f"[!] Discord alert failed: {response.status_code}")
        
        except Exception as e:
            print(f"[!] Error sending Discord alert: {e}")
    
    def send_telegram_alert(self, leak_data: Dict):
        """Send alert to Telegram"""
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return
        
        try:
            message = f"""
🚨 *Potential Data Leak Detected*

*Source:* {leak_data['source']}
*Threat Score:* {leak_data['analysis']['threat_score']}
*URL:* {leak_data['url']}

*Keywords:* {', '.join(leak_data['analysis']['keywords_found'][:5])}
*Emails Found:* {leak_data['analysis']['email_count']}
*Credential Patterns:* {leak_data['analysis']['credential_patterns']}

*Preview:*
```
{leak_data['content_preview'][:300]}
```
            """.strip()
            
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                print("[✓] Telegram alert sent successfully")
            else:
                print(f"[!] Telegram alert failed: {response.status_code}")
        
        except Exception as e:
            print(f"[!] Error sending Telegram alert: {e}")
    
    def monitor(self, interval: int = 300):
        """
        Start monitoring paste sites
        
        Args:
            interval: Check interval in seconds (default: 5 minutes)
        """
        print("[*] Starting Paste-Site Leaks Monitor")
        print(f"[*] Check interval: {interval} seconds")
        print(f"[*] Monitoring keywords: {', '.join(self.keywords[:5])}...")
        print()
        
        iteration = 0
        
        while True:
            try:
                iteration += 1
                print(f"\n[*] Scan iteration #{iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                all_leaks = []
                
               
                print("[*] Scanning Pastebin...")
                pastebin_leaks = self.scrape_pastebin_recent()
                all_leaks.extend(pastebin_leaks)
                
                
                print("[*] Scanning GhostBin...")
                ghostbin_leaks = self.scrape_ghostbin()
                all_leaks.extend(ghostbin_leaks)
                
               
                if all_leaks:
                    print(f"\n[!] Found {len(all_leaks)} potential leak(s)!")
                    
                    for leak in all_leaks:
                        print(f"\n--- Leak Detected ---")
                        print(f"Source: {leak['source']}")
                        print(f"URL: {leak['url']}")
                        print(f"Threat Score: {leak['analysis']['threat_score']}")
                        print(f"Keywords: {', '.join(leak['analysis']['keywords_found'][:5])}")
                        print(f"Emails: {leak['analysis']['email_count']}")
                        
                      
                        self.send_discord_alert(leak)
                        self.send_telegram_alert(leak)
                else:
                    print("[✓] No suspicious pastes found in this scan")
                
                print(f"\n[*] Waiting {interval} seconds until next scan...")
                time.sleep(interval)
            
            except KeyboardInterrupt:
                print("\n[*] Monitoring stopped by user")
                break
            except Exception as e:
                print(f"\n[!] Error in monitoring loop: {e}")
                time.sleep(60)


if __name__ == "__main__":
    
    DISCORD_WEBHOOK = " "  # Add your Discord webhook URL
    TELEGRAM_BOT_TOKEN = " "  # Add your Telegram bot token
    TELEGRAM_CHAT_ID = " "  # Add your Telegram chat ID
    

    monitor = PasteMonitor(
        discord_webhook=DISCORD_WEBHOOK,
        telegram_bot_token=TELEGRAM_BOT_TOKEN,
        telegram_chat_id=TELEGRAM_CHAT_ID
    )
    
    monitor.monitor(interval=300)