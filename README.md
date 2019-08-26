# bookmark
simple bookmark manager webservice in Go

CURL TESTS: create user: curl.exe -d "username=chris&password=123" -X POST http://localhost:10000/add_user

add bookmark: curl.exe -d "url=www.cisco.com" -X POST http://localhost:10000/add_bookmark --user chris:123

update bookmark by adding or deleting tags: curl.exe -d "action=add&url=www.cisco.com&tagname=work" -X POST http://localhost:10000/update_bookmark --user chris:123 curl.exe -d "action=delete&url=www.cisco.com&tagname=work" -X POST http://localhost:10000/update_bookmark --user chris:123

list bookmarks: curl.exe -X GET http://localhost:10000/list_bookmarks?tags= --user chris:123

list bookmarks filtered by tag curl.exe -X GET http://localhost:10000/list_bookmarks?tags=work --user chris:123

BASIC UI: visit http://localhost:10000/ to create an account, sign in and start adding bookmarks
