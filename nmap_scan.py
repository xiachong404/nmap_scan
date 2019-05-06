#-*- coding:utf-8 -*-

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import sqlite3,sys,logging,time,getopt,os

# ----------------------------------------------
# 根据自己的需求配置参数

# 错误日志
global_log_name = 'log.log'
# db
global_sqlite_db = 'db.db'
# 默认读取的扫描文件
target_scan_file = 'targets.txt'
# nmap扫描参数
global_nmap_scan_para = "-sV -sS -O -P0"

logging_level = logging.INFO
global_out_path = sys.path[0]
global_added_list = []
global_changed_list = []
global_removed_list = []
# ----------------------------------------------
# usage
def Usage():
	print '''
	####################################################################
	#                                                                  #
	#                           Nmap Scanner                           #
	#                            By : Gavin                            #
	#                                                                  #
	####################################################################
	Usage:
	   python %s 
	Prompt:
	   -t [targets.txt] Target scan File, Default is "%s".
	--------------------------------------------------------------------
	'''%(os.path.basename(__file__),target_scan_file)
	sys.exit()

# 日志模块
class _logging:
	def __init__(self,logname=global_log_name):
		# print logname
		logging.basicConfig(level=logging_level,
			format='%(asctime)s %(levelname)s %(message)s',
			datefmt='%Y/%m/%d %H:%M:%S',
			filename=global_out_path + '/%s'%logname,
			filemode='a')
		logging.getLogger("paramiko").setLevel(logging.WARNING)
		self.log_obj = logging
		self.log_obj_fun()
	def log_obj_fun(self):
		return self.log_obj

# sqlite3模块
class _sqlite_client:
	def __init__(self,db_file = global_sqlite_db):
		try:
			self.conn = sqlite3.connect(db_file)
			self.cursor = self.conn.cursor()
		except Exception as e:
			print '\r-------------------------------------------------'
			print '[!] sqlite_db_connect Error.'
			print e
			_logging_obj.exception('[!] sqlite_db_connect Error: %s' % str(e))
			sys.exit()

	def sql_query(self,exec_sql):
		try:
			self.cursor.execute(exec_sql)
			return self.cursor.fetchall()
		except Exception as e:
			print '\r-------------------------------------------------'
			print '[!] sqlite_sql_query Error.'
			print e
			_logging_obj.exception('[!] sqlite_sql_query Error: %s' % str(e))
			sys.exit()

	def sql_insert(self,insert_sql,value_args):
		try:
			self.conn.execute(insert_sql,value_args)
			self.conn.commit()
		except Exception as e:
			print '\r-------------------------------------------------'
			print '[!] sqlite_sql_insert Error.'
			print e
			_logging_obj.exception('[!] sqlite_sql_insert Error: %s' % str(e))
			sys.exit()

	def sql_update(self,update_sql):
		try:
			self.conn.execute(update_sql)
			self.conn.commit()
		except Exception as e:
			print '\r-------------------------------------------------'
			print '[!] sqlite_sql_update Error.'
			print e
			_logging_obj.exception('[!] sqlite_sql_update Error: %s' % str(e))
			sys.exit()

	def update_time(self,target):
		try:
			update_time_sql = "update nmap_scan set update_time=datetime('now', 'localtime') where host='%s'"%target
			self.sql_update(update_time_sql)
			self.sql_obj_close()
		except Exception as e:
			print '\r-------------------------------------------------'
			print '[!] update_time Error.'
			print e
			_logging_obj.exception('[!] update_time Error: %s' % str(e))
			sys.exit()

	def sql_obj_close(self):
		try:
			self.cursor.close()
			self.conn.close()
		except Exception,e:
			print e
			pass


def nested_obj(objname):
	try:
		rval = None
		splitted = objname.split("::")
		if len(splitted) == 2:
			rval = splitted
		return rval
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] nested_obj Error.'
		print e
		_logging_obj.exception('[!] nested_obj Error: %s' % str(e))
		pass

def print_diff_added(obj1, obj2, added):
	try:
		for akey in added:
			nested = nested_obj(akey)
			if nested is not None:
				if nested[0] == 'NmapHost':
					subobj1 = obj1.get_host_byid(nested[1])
				elif nested[0] == 'NmapService':
					subobj1 = obj1.get_service_byid(nested[1])
				added_str = "[+] {0}".format(subobj1)
				global_added_list.append(added_str)
				# print added_str
			else:
				added_str = "[+] {0} {1}: {2}".format(obj1, akey, getattr(obj1, akey))
				global_added_list.append(added_str)
				# print added_str
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] print_diff_added Error.'
		print e
		_logging_obj.exception('[!] print_diff_added Error: %s' % str(e))
		pass

def print_diff_removed(obj1, obj2, removed):
	try:
		for rkey in removed:
			nested = nested_obj(rkey)
			if nested is not None:
				if nested[0] == 'NmapHost':
					subobj2 = obj2.get_host_byid(nested[1])
				elif nested[0] == 'NmapService':
					subobj2 = obj2.get_service_byid(nested[1])
				removed_str = "[-] {0}".format(subobj2)
				global_removed_list.append(removed_str)
				# print removed_str
			else:
				removed_str = "[-] {0} {1}: {2}".format(obj2, rkey, getattr(obj2, rkey))
				global_removed_list.append(removed_str)
				# print removed_str
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] print_diff_removed Error.'
		print e
		_logging_obj.exception('[!] print_diff_removed Error: %s' % str(e))
		pass

def print_diff_changed(obj1, obj2, changes):
	try:
		for mkey in changes:
			nested = nested_obj(mkey)
			if nested is not None:
				if nested[0] == 'NmapHost':
					subobj1 = obj1.get_host_byid(nested[1])
					subobj2 = obj2.get_host_byid(nested[1])
				elif nested[0] == 'NmapService':
					subobj1 = obj1.get_service_byid(nested[1])
					subobj2 = obj2.get_service_byid(nested[1])
				print_diff(subobj1, subobj2)
			else:
				changed_str = "[~] {0} {1}: {2} => {3}".format(obj1, mkey,getattr(obj2, mkey),getattr(obj1, mkey))
				# print changed_str
				global_changed_list.append(changed_str)
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] print_diff_changed Error.'
		print e
		_logging_obj.exception('[!] print_diff_changed Error: %s' % str(e))
		pass

def print_diff(obj1, obj2):
	try:
		ndiff = obj1.diff(obj2)
		changed_list = print_diff_changed(obj1, obj2, ndiff.changed())
		added_list = print_diff_added(obj1, obj2, ndiff.added())
		removed_list = print_diff_removed(obj1, obj2, ndiff.removed())
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] print_diff Error.'
		print e
		_logging_obj.exception('[!] print_diff Error: %s' % str(e))
		pass

def diff_nmap_xml(old_xml_str,new_xml_str):
	try:
		added_str = ''
		removed_str = ''
		changed_str = ''
		oldrep = NmapParser.parse_fromstring(old_xml_str)
		newrep = NmapParser.parse_fromstring(new_xml_str)
		print_diff(newrep, oldrep)

		if len(global_added_list):
			added_str = '\n'.join(global_added_list)+'\n'
		if len(global_removed_list):
			removed_str = '\n'.join(global_removed_list)+'\n'
		if len(global_changed_list):
			changed_str = '\n'.join(global_changed_list)+'\n'

		s1 = '-------------------------------------------------'
		s2 = "'[+]' means values were added"
		s3 = "'[-]' means values were removed"
		s4 = "'[~]' means values changed"
		all_diff_str = s1+'\n'+s2+'\n'+s3+'\n'+s4+'\n\n'+added_str+removed_str+changed_str

		print all_diff_str
		return all_diff_str
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] diff_nmap_xml Error.'
		print e
		_logging_obj.exception('[!] diff_nmap_xml Error: %s' % str(e))
		pass

# 更新xml_result
def control_xml_result_sqlite(target,new_xml_str):
	try:
		all_diff_str = ''
		query_target_sql = "select xml_result from nmap_scan where host='%s'"%target
		sql_obj = _sqlite_client()
		xml_list = sql_obj.sql_query(query_target_sql)
		if len(xml_list):
			old_xml_str = xml_list[0][0]
			# 与上一次扫描对比
			all_diff_str = diff_nmap_xml(str(old_xml_str),str(new_xml_str))
			# 将新扫描的xml数据更新入库
			update_xml_sql = "update nmap_scan set xml_result='%s' where host='%s'"%(new_xml_str,target)
			sql_obj.sql_update(update_xml_sql)
			# 将对比数据入库
			if all_diff_str:
				update_diff_sql = 'update nmap_scan set diff_result="%s" where host="%s"'%(all_diff_str,target)
				sql_obj.sql_update(update_diff_sql)
		else:
			insert_xml_sql = "insert into nmap_scan(host,xml_result) values (?,?)"
			args = (target,new_xml_str)
			sql_obj.sql_insert(insert_xml_sql,args)

		sql_obj.sql_obj_close()
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] control_xml_result_sqlite Error.'
		print e
		_logging_obj.exception('[!] control_xml_result_sqlite Error: %s' % str(e))
		sys.exit()

# 格式化展示结果入库
def control_parse_result_sqlite(target,parse_str):
	try:
		query_target_sql = "select id from nmap_scan where host='%s'"%target
		sql_obj = _sqlite_client()
		host_list = sql_obj.sql_query(query_target_sql)
		if len(host_list):
			update_xml_sql = "update nmap_scan set parse_result='%s' where host='%s'"%(parse_str,target)
			sql_obj.sql_update(update_xml_sql)
		sql_obj.sql_obj_close()
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] control_parse_result_sqlite Error.'
		print e
		_logging_obj.exception('[!] control_parse_result_sqlite Error: %s' % str(e))
		sys.exit()
# nmap 扫描
def nmap_do_scan(target, options):
	try:
		nm = NmapProcess(target, options)
		rc = nm.run_background()

		print '\r\n##################################################'
		print '[+] Start to Scan --> %s'%target
		_logging_obj.info('\r\n##################################################')
		_logging_obj.info('[+] Start to Scan --> %s'%target)

		while nm.is_alive():
			print "Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,nm.progress)
			time.sleep(2)

		print '[+] End to Scan --> %s\n'%target
		_logging_obj.info('[+] End to Scan --> %s'%target)
		# rc = nm.run()
		# 判断是否扫描出错
		if nm._NmapProcess__stderr != '':
			print '\r-------------------------------------------------'
			print "nmap scan failed: %s" % (nm._NmapProcess__stderr)
			_logging_obj.error('\r-------------------------------------------------')
			_logging_obj.error("nmap scan failed: %s" % (nm._NmapProcess__stderr))
			sys.exit()

		return nm.stdout

	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] nmap_do_scan Error.'
		print e
		_logging_obj.exception('[!] nmap_do_scan Error: %s' % str(e))
		sys.exit()

	# try:
	# 	parsed = NmapParser.parse(nm.stdout)
	# except NmapParserException as e:
	# 	print "Exception raised while parsing scan: %s" % (e.msg)
	# return parsed

# 解析扫描结果xml
def parse_scan_xml(nmap_report):
	try:
		str1 = "Starting Nmap {0} ( http://nmap.org ) at {1}".format(
			nmap_report._nmaprun['version'],
			nmap_report._nmaprun['startstr'])

		for host in nmap_report.hosts:
			if len(host.hostnames):
				tmp_host = host.hostnames.pop()
			else:
				tmp_host = host.address

			str2 = "Nmap scan report for {0} ({1})".format(
				tmp_host,
				host.address)
			str3 = "Host is {0}.".format(host.status)
			str4 = "  PORT     STATE         SERVICE"
			for serv in host.services:
				pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
						str(serv.port),
						serv.protocol,
						serv.state,
						serv.service)
				if len(serv.banner):
					pserv += " ({0})".format(serv.banner)
				str5 = pserv
		str6 = nmap_report.summary
		parse_print = str1+'\n'+str2+'\n'+str3+'\n'+str4+'\n'+str5+'\n'+str6
		return parse_print

	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] parse_scan_xml Error.'
		print e
		_logging_obj.exception('[!] parse_scan_xml Error: %s' % str(e))
		sys.exit()

def test_mod(target):
	query_target_sql = "select * from nmap_scan where host='%s'"%target
	sql_obj = _sqlite_client()
	host_list = sql_obj.sql_query(query_target_sql)
	sql_obj.sql_obj_close()
	print host_list

# 获取扫描列表
def get_parameter():
	global target_scan_file
	all_scan_list =[]
	try:
		opts,args = getopt.getopt(sys.argv[1:],"t:")
	except:
		Usage()
	for o,a in opts:
		if o == "-t":
			target_scan_file = a
	try:
		f_obj = open(target_scan_file,'r')
		for line in f_obj.readlines():
			if line:
				line = line.strip()
				all_scan_list.append(line)
		f_obj.close()
		return all_scan_list
	except Exception as e:
		print '\r-------------------------------------------------'
		print '[!] get_parameter_read_targets_file Error.'
		print e
		_logging_obj.exception('[!] get_parameter_read_targets_file Error: %s' % str(e))
		sys.exit()
# main
if __name__ == "__main__":
	_logging_obj = _logging().log_obj

	all_scan_list = get_parameter()
	if len(all_scan_list) == 0:
		print "[!] '%s' is Null !!!"%target_scan_file
		sys.exit()
	for target in all_scan_list:
		# target = "192.168.199.215"

		# 扫描目标
		xml_str = nmap_do_scan(target,global_nmap_scan_para)
		# 更新xml进库
		control_xml_result_sqlite(target,xml_str)
		# 解析xml
		parsed_report = NmapParser.parse(xml_str)
		# 格式化展示解析结果
		parse_print = parse_scan_xml(parsed_report)
		print '\r-------------------------------------------------'
		print parse_print
		# 格式化展示结果入库
		control_parse_result_sqlite(target,parse_print)
		# 更新时间字段
		_sqlite_client().update_time(target)

		# test模块 可以删除
		# test_mod(target)
