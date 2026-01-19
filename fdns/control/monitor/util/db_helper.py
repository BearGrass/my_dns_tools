#coding=utf-8

import MySQLdb


class DbHelper(object):
    
    def __init__(self, host, user, passwd, dbname, charset=None, port=3306):
        self.__host = host
        self.__user = user
        self.__passwd = passwd
        self.__dbname = dbname
        self.__port = port
        self.__conn = None
        self.__charset = None
        if None != charset:
            self.__charset = charset
        if self.__conn is None:
            self.connect()

    def connect(self):
        try:
            if None != self.__charset:
                self.__conn = MySQLdb.connect(host=self.__host, user=self.__user, passwd=self.__passwd,
                                              db=self.__dbname, port=self.__port, charset=self.__charset)
            else:
                self.__conn = MySQLdb.connect(host=self.__host, user=self.__user, passwd=self.__passwd,
                                              db=self.__dbname, port=self.__port)
        except Exception, e:
            raise
            
    def execute(self, sql):
        if self.__conn is None:
            self.connect()
        try:
            self.__conn.ping()
        except:
            self.__conn.close()
            self.connect()
        try:
            cursor = self.__conn.cursor(cursorclass=MySQLdb.cursors.DictCursor)
            #log.info("cmd:%s" % sql)
            cursor.execute(sql)
            res = cursor.fetchall()
            cursor.close()
            self.__conn.commit()

            return res
        except Exception,e:
            raise e
        
    def select_insert(self, sql, domain):
        if self.__conn is None:
            self.connect()
        try:
            self.__conn.ping()
        except:
            self.__conn.close()
            self.connect()
        try:
            cursor = self.__conn.cursor(cursorclass=MySQLdb.cursors.DictCursor)
            n = cursor.execute(sql, domain)
            cursor.close()
            return n
        except Exception, e:
            raise e
            
    def close(self):
        self.__conn.close()
        
