package main

import (
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"strings"
	"text/template"
)

var database *sql.DB
var store *sessions.CookieStore
var tpl *template.Template
type User struct {
	Username      string
	Password	  string
	Authenticated bool
}
type UserData struct {
	Id 			int `db:id`
	Username string `json:"username", db:"username"`
	Password string `json:"password", db:"password"`
}
type Bookmark struct {
	Url   		string `json:"url", db:"url"`
	TagName   	string `json:"tag", db:"tagName"`
	BookmarkId 	   int `db:"bookmarkId"`
	TagId 		   int `db:tagId`
}
func handleRequests(){
	router := mux.NewRouter()
	router.HandleFunc("/", index)
	router.HandleFunc("/add_user", AddUser).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/logout", AuthMiddleware(logout)).Methods("GET")
	router.HandleFunc("/add_bookmark", AuthMiddleware(AddBookmark)).Methods("POST")
	router.HandleFunc("/update_bookmark", AuthMiddleware(UpdateBookmark)).Methods("PUT")
	router.HandleFunc("/delete_tag", AuthMiddleware(DeleteTag)).Methods("DELETE")
	router.HandleFunc("/list_bookmarks", AuthMiddleware(ListBookmarks)).Methods("GET")
	log.Fatal(http.ListenAndServe(":10000", router))
}
func getUser(s *sessions.Session) User {
	val := s.Values["user"]
	fmt.Println("val",val)
	user, ok := val.(User)
	if !ok {
		fmt.Println("did not find user session")
		return User{Authenticated: false}
	}
	fmt.Println(val.(User))
	fmt.Println("user.username",user.Username)
	return user
}
//if basic auth headers exists, proceed to pass request to services
//if not, check if session user is authenticated
func AuthMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, _ := r.BasicAuth()
		fmt.Println(r.BasicAuth())
		if  username=="" || !checkUsernameAndPassword(username, password) {
			//w.Header().Set("WWW-Authenticate", `Basic realm="Please enter your username and password for this site"`)
			//w.WriteHeader(401)
			//w.Write([]byte("Unauthorised.\n"))
			//w.Write([]byte("checking session instead.\n"))
			session, err := store.Get(r, "cookie-name")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			user := getUser(session)
			fmt.Println(user)
			if auth := user.Authenticated; !auth {
				session.AddFlash("You don't have access!")
				err = session.Save(r, w)
				if err != nil {
					fmt.Printf("You don't have access!")
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				fmt.Printf("You don't have access!")
				http.Redirect(w, r, "/forbidden", http.StatusFound)
				return
			}
			fmt.Println("authenticated via user session")
			handler(w, r)
			return
		}
		fmt.Println("authenticated via basic auth")
		handler(w, r)
	}
}
func checkUsernameAndPassword(username, password string) bool {
	fmt.Println("[checkUsernameAndPassword]")
	correctPassword := retrieveUserPassword(username)
	return password == correctPassword
}
func index(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
	}
	user := getUser(session)
	fmt.Println("[serving main page]",user)
	tpl.ExecuteTemplate(w, "index.gohtml", user)
}
func AddUser( w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	res , _ := database.Exec("INSERT INTO users(username,password) VALUES (?,?)",username,password)
	fmt.Println(res)
	fmt.Fprintf(w, "User successfully added")
	http.Redirect(w, r, "/", http.StatusFound)
}
func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := retrieveUserPassword(username)
	session, err := store.Get(r, "cookie-name")
	if err != nil {
	}
	// Where authentication could be done
	if r.FormValue("password") != password {
		if r.FormValue("password") == "" {
			session.AddFlash("Must enter a password")
		}
		session.AddFlash("The password was incorrect")
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}
	user := &User{
		Username:	username,
		Password:	password,
		Authenticated:	true,
	}
	session.Values["user"] = user
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("login successful")
	//expiration := time.Now().Add(365 * 24 * time.Hour)
	//cookie := http.Cookie{Name: "username", Value: username, Expires: expiration}
	//http.SetCookie(w, &cookie)
	//cookie2:= http.Cookie{Name: "password", Value: password, Expires: expiration}
	//http.SetCookie(w, &cookie2)
	http.Redirect(w, r, "/", http.StatusFound)
}
func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["user"] = User{}
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
func AddBookmark( w http.ResponseWriter, r *http.Request){
	fmt.Println("add bookmark service reached")
	url := r.FormValue("url")
	username := getUserName(w,r)
	userId := retrieveUserId(username)
	fmt.Println(url," inserted for user", username )
	res, _ := database.Exec("INSERT INTO bookmarks(url,userid) VALUES(?,?)",url,userId)
	fmt.Println(res)
	http.Redirect(w, r, "/", http.StatusFound)
	//fmt.Fprintf(w, "Bookmark added")
}
func UpdateBookmark(w http.ResponseWriter, r *http.Request){
	fmt.Println("update bookmark service hit")
	url := r.FormValue("url")
	tagname := r.FormValue("tagname")
	username := getUserName(w,r)
	userId := retrieveUserId(username)
	if userId != 0 {
		bookmarkId := retrieveBookmarkId(url, userId)
		res, _ := database.Exec("INSERT OR IGNORE INTO tags(name) VALUES(?)",tagname)
		if res != nil {}
		var tagId int
		err := database.QueryRow("SELECT  id from tags WHERE  name=$1",tagname).Scan(&tagId)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(tagId,bookmarkId)
		fmt.Println(err)
		res2, _ := database.Exec("INSERT INTO tag_bookmark(tagid,bookmarkid) VALUES(?,?)",tagId,bookmarkId)
		if res2 != nil {}
		fmt.Fprintf(w, "tag added")
	}else {
		fmt.Fprintf(w, "password incorrect")
	}
}
func DeleteTag(w http.ResponseWriter, r *http.Request){
	fmt.Println("deleting tag from bookmark")
	fmt.Println(r)
	tagname := r.URL.Query().Get("tag")
	url :=  r.URL.Query().Get("url")
	//url := r.FormValue("url")
	//tagname := r.FormValue("tagname")
	fmt.Println(url,tagname)
	username := getUserName(w,r)
	userId := retrieveUserId(username)
	if userId != 0 {
		bookmarkId := retrieveBookmarkId(url, userId)
		var tagId int
		err := database.QueryRow("SELECT  id from tags WHERE  name=$1", tagname).Scan(&tagId)
		if err != nil {
			fmt.Println(err)
		}
		res2, _ := database.Exec("DELETE FROM tag_bookmark WHERE tagid=$1 AND bookmarkId=$2", tagId, bookmarkId)
		fmt.Println(res2)
		fmt.Fprintf(w, "tag deleted")
	}

}
func ListBookmarks(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListBookmarks service hit")
	tags := r.URL.Query().Get("tags")
	fmt.Println("tags:",tags)
	username := getUserName(w,r)
	fmt.Println("username:",username)
	userId := retrieveUserId(username)
	fmt.Println("userId:",userId)
	var bookmark Bookmark
	queryString := fmt.Sprintf("SELECT bookmarks.id as bookmarkId, bookmarks.url as url, " +
		"coalesce(tags.name,'') AS tagName, coalesce(tags.id,0) AS tagId  FROM bookmarks  " +
		"LEFT JOIN tag_bookmark  " +
		"ON tag_bookmark.bookmarkid = bookmarks.id LEFT JOIN tags  " +
		"ON tags.id = tag_bookmark.tagid WHERE bookmarks.userid=%d", userId)
	//if tags != "" {
	//	oldQueryString := queryString
	//	queryString = fmt.Sprintf(oldQueryString+" AND tagName IN (%s)", "'"+
	//		strings.Replace(tags, ",", "','", -1)+"'")
	//}
	rows, err := database.Query(queryString)
	if err != nil && err != sql.ErrNoRows {
		// log the error
		fmt.Fprintf(w, "" )
		return
	}
	defer rows.Close()
	bookmarkResults := make(map[string][]string)
	//tagResults := make(map[int][]string)
	for rows.Next(){
		err := rows.Scan(&bookmark.BookmarkId,&bookmark.Url,&bookmark.TagName,&bookmark.TagId)
		if err != nil && err != sql.ErrNoRows {
			// log the error
		}
		//bookmarkRecord := []string{bookmark.tagId,bookmark.tagName}
		//bookmarkRecord[bookmark.tagId]=bookmark.tagName
		//bookmarkResults[bookmark.url] = append(bookmarkResults[bookmark.url], bookmarkRecord)
		bookmarkResults[bookmark.Url] = append(bookmarkResults[bookmark.Url], bookmark.TagName)
		//fmt.Println(bookmark.Url, bookmark.TagName)
	}
	for key := range bookmarkResults {
		if len(tags) != 0  {
			//&& !strings.Contains(strings.Join(bookmarkResults[key], ","),tags)
			tagsList := strings.Split(tags, ",")
			//tagName = bookmarkResults[key]
			for _, tag := range tagsList {
				if !stringInSlice(tag,bookmarkResults[key]){
					delete(bookmarkResults, key)
				}
			}
		}
	}
	type bookmarkJson struct {
		Url   		string `json:"url"`
		TagName   	[]string `json:"tagName"`
	}
	var data []bookmarkJson
	for key := range bookmarkResults {
		bookmarkj := bookmarkJson{Url: key, TagName: bookmarkResults[key]}
		data=append(data, bookmarkj )
	}
	bJsondata, _ := json.Marshal(data)
	jsonData := string(bJsondata)
	fmt.Println(jsonData)
	fmt.Fprintf(w, jsonData )

}
func retrieveUserPassword(username string) string {
	var dbUser UserData
	err := database.QueryRow("SELECT password, id FROM users WHERE  username=$1", username).
		Scan(&dbUser.Password,&dbUser.Id)
	if err != nil {
		fmt.Println("[retrieveUserPassword] user not found in DB",username)
		panic(err)
	}
	return dbUser.Password
}
func retrieveUserId(username string) int {
	var dbUser UserData
	err := database.QueryRow("SELECT  id FROM users WHERE  username=$1", username).
		Scan(&dbUser.Id)
	if err != nil {
		fmt.Println("[retrieveUserId] user not found in DB",username)
		panic(err)
	}
	return dbUser.Id
}
func retrieveBookmarkId(url string, userId int) int {
	var bookmarkId int
	err := database.QueryRow("SELECT id FROM bookmarks WHERE url=$1 AND userid=$2",url,userId).Scan(&bookmarkId)
	fmt.Println(err)
	return bookmarkId
}
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func getUserName (w http.ResponseWriter,r *http.Request) string {
	var username string
	username, _, ok := r.BasicAuth()
	if !ok {
		session, err := store.Get(r, "cookie-name")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return ""
		}
		fmt.Println("username retrieved from session")
		user := getUser(session)
		username = user.Username
		return username
	}
	fmt.Println("username retrieved from basic auth")
	return username
}
func initDB(){
	database, _ = sql.Open("sqlite3", "./cisco.db")
	createUsersTable, _ := database.Prepare("CREATE TABLE IF NOT EXISTS users (" +
		"id INTEGER PRIMARY KEY AUTOINCREMENT," +
		"username VARCHAR (20)     NOT NULL, " +
		"password VARCHAR (20)     NOT NULL)")
	createUsersTable.Exec()
	createBookmarksTable, _ := database.Prepare("CREATE TABLE IF NOT EXISTS bookmarks " +
		"(id INTEGER PRIMARY KEY AUTOINCREMENT," +
		"url VARCHAR (70) , userid REFERENCES users(id),CONSTRAINT unq UNIQUE (url, userid))")
	createBookmarksTable.Exec()
	createTagsTable, _ := database.Prepare("CREATE TABLE IF NOT EXISTS tags (" +
		"id INTEGER PRIMARY KEY AUTOINCREMENT, " +
		"name VARCHAR (20) NOT NULL UNIQUE)")
	createTagsTable.Exec()
	createTagbookmarkTable, _ := database.Prepare( "CREATE TABLE IF NOT EXISTS tag_bookmark " +
		"(tagid INTEGER, bookmarkid INTEGER, UNIQUE (tagid, bookmarkid) )")
	//createTagbookmarkTable, _ := database.Prepare( "CREATE TABLE IF NOT EXISTS tag_bookmark " +
	//	"(tagid REFERENCES tags(id), bookmarkid REFERENCES bookmarks(id), PRIMARY KEY(tagid, bookmarkid) )")
	createTagbookmarkTable.Exec()
	fmt.Println("DB initialized")
}
func initSession(){
	authKeyOne := securecookie.GenerateRandomKey(64)
	encryptionKeyOne := securecookie.GenerateRandomKey(32)
	store = sessions.NewCookieStore(
		authKeyOne,
		encryptionKeyOne,
	)
	store.Options = &sessions.Options{
		MaxAge:   600 * 15,
		HttpOnly: true,
	}
	gob.Register(User{})
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
}
func main() {
	initDB()
	initSession()
	handleRequests()
}
