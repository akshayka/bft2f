proto:
	protoc  --python_out=./ bft2f.proto
thrift:
	thrift -r --gen py auth_service.thrift