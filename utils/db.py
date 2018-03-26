from pymongo import MongoClient
import ast

class Database_update:
	def __init__(self):
		self.client = MongoClient('localhost',27017)
		self.db = self.client.apiscan

	def fetch_records(self):
		records = self.db.vulnerbilities.find({})
		if records:
			for data in records:
				data.pop('_id')
				print data

	def insert_record(self,data):
		try:
			self.db.vulnerabilities.insert(data)
		except Exception as e:
			raise e

	def update_record(self,find,update):
		try:
			self.db.scanids.update(find,update)
		except Exception as e:
			raise e