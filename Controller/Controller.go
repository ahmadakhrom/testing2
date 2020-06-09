package Controller

import (
	"Testing/Database"
	"Testing/Models"
	"fmt"
	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// ############################################     start of function     ############################################

//variable response of expression
type M map[string]interface{}

//Generating password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

//Comparing password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//set session on cookies
const SESSION_ID = "_sess"

func newCookieStore() *sessions.CookieStore {
	authKey := []byte("my-auth-key-very-secret")
	encryptionKey := []byte("my-encryption-key-very-secret123")
	store := sessions.NewCookieStore(authKey, encryptionKey)
	store.Options.Path = "/"
	store.Options.MaxAge = 3600 * 1 //1 hours
	store.Options.HttpOnly = true
	return store
}

//generate random string and set length for file name upload
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func GenerateStringFile(length int) string {
	return StringWithCharset(length, charset)
}

//end of setting jwt token

// ############################################     end of function     ############################################
// ############################################     start of code     ############################################

func Login(c echo.Context) error {
	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		return c.Render(http.StatusOK, "Dashboard", nil)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}

	return c.Render(http.StatusInternalServerError, "Login", nil)
}

func Logout(c echo.Context) error {
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	session.Options.MaxAge = -1
	session.Save(c.Request(), c.Response())
	return c.Render(http.StatusOK, "Login", nil)
}

func Dashboardlog(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	if username == "p" || password == "p"{
		//return c.String(http.StatusOK, "directing to dashboard admin page..")
		return c.String(http.StatusOK, "welcome...."+username)
	}
	//return c.String(http.StatusOK, "directing to dashboard admin page..")
	return c.String(http.StatusOK, "unauthorize")
}

func Corona(c echo.Context) error {
	//var resObject Models.CoronaIndo
	//
	////total positive
	//resUrl, err := http.Get("https://api.kawalcorona.com/indonesia")
	//if err != nil {
	//	fmt.Print(err.Error())
	//	os.Exit(1)
	//}
	//
	//resData, err := ioutil.ReadAll(resUrl.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//json.Unmarshal(resData, &resObject)
	//
	//data := M{"v":resObject.Name}
	//log.Println("tessssssss :",resObject.Name)

	return c.Render(http.StatusOK,"corona", nil)
}

func CoronaGlobal(c echo.Context) error {
	////fulldetail global
	//resGlobal, err := http.Get("https://api.kawalcorona.com/")
	//if err != nil {
	//	fmt.Print(err.Error())
	//	os.Exit(1)
	//}
	//resDataGlobal, err := ioutil.ReadAll(resGlobal.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//var resObjectGlobal Models.CoronaGlobalRes
	//
	//json.Unmarshal(resDataGlobal, &resObjectGlobal)
	//data := M{"resIDCountry": resObjectGlobal.Attributes}
	//log.Println(resObjectGlobal.Attributes)

	return c.JSON(http.StatusOK, nil)
}

func Employee(c echo.Context) error {
	//// Build the request
	//res, err := http.Get("http://dummy.restapiexample.com/api/v1/employees")
	//if err != nil {
	//	fmt.Print(err.Error())
	//	os.Exit(1)
	//}
	//
	//resData, err := ioutil.ReadAll(res.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//var resObj Models.Employee
	//json.Unmarshal(resData, &resObj)
	//
	//fmt.Println(resObj.Status)
	//
	//for i := 1; i < len(resObj.Data); i++ {
	//	//fmt.Println(resObj.Data[i].ID + "|" + resObj.Data[i].EmployeeName+ "|" + resObj.Data[i].EmployeeAge+ "|" + resObj.Data[i].EmployeeSalary)
	//	res1 := resObj.Data[i].ID
	//	res2 := resObj.Data[i].EmployeeName
	//	res3 := resObj.Data[i].EmployeeAge
	//	res4 := resObj.Data[i].EmployeeSalary
	//
	//	data := M{"res1": res1, "res2": res2, "res3": res3, "res4": res4}
	//	return c.Render(http.StatusOK, "corona", data)
	//}
	return c.Render(http.StatusOK, "corona", nil)
}

func Dashboards(c echo.Context) error {
	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		return c.Render(http.StatusOK, "Dashboard", nil)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking
	return c.Render(http.StatusOK, "Login", nil)
}

func DashboardStaff(c echo.Context) error {
	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		return c.Render(http.StatusOK, "Dashboard", nil)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking

	return c.Render(http.StatusOK, "Login", nil)
}

func DashboardMember(c echo.Context) error {
	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		return c.Render(http.StatusOK, "Dashboard", nil)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking
	return c.Render(http.StatusOK, "Login", nil)
}

//#############################################################################################################

func Dashboard(c echo.Context) error {
	db := database.Connect()
	Username := c.FormValue("username")
	Password := c.FormValue("password")

	var FirstnameDB, UsernameDB, PasswordDB, PrivilegeDB string

	//check filled form with database
	errQuery := db.QueryRow("select Firstname,Username, Password, privilege from users where Username = ?", Username).
		Scan(&FirstnameDB, &UsernameDB, &PasswordDB, &PrivilegeDB)

	if Username == "" {
		log.Println("Username cannot be empty")
		Response := "Username cannot be empty!"
		Data := M{"errorUsername": Response}
		return c.Render(http.StatusOK, "Login", Data)
	}

	if errQuery != nil {
		log.Println("Unknown username")
		Response := "Wrong Username!"
		Data := M{"errorUsername": Response}
		//log.Println(HashPassword(Password)) //for admin get instant password from form login
		return c.Render(http.StatusOK, "Login", Data)
	}

	if Password == "" {
		log.Println("Password cannot be empty")
		Response := "Password cannot be empty!"
		Data := M{"errorPassword": Response}
		return c.Render(http.StatusOK, "Login", Data)
	}

	if PasswordCompared := CheckPasswordHash(Password, PasswordDB); PasswordCompared == false {
		log.Println("Wrong Password")
		Response := "Wrong Password!"
		Data := M{"errorPassword": Response}
		return c.Render(http.StatusOK, "Login", Data)
	}

	Privilege, _ := strconv.Atoi(PrivilegeDB)
	switch Privilege {
	case 1:
		//log.Println("token :", t)
		//log.Println("direct to admin page")
		//start of session
		store := newCookieStore()
		session, _ := store.Get(c.Request(), SESSION_ID)

		session.Values["Privilege"] = PrivilegeDB
		session.Values["Username"] = UsernameDB
		session.Save(c.Request(), c.Response())
		//usernameSess := fmt.Sprintf("%s", UsernameDB)
		//privilegeUser := fmt.Sprintf("%s", PrivilegeDB)
		//log.Println("your privilege :", usernameSess)
		//log.Println("your privilege :", privilegeUser)
		//end of session

		usr, responseReg := FirstnameDB, "You may just type like alphanumeric underscore and dot"
		data := M{"resSession": responseReg, "username": usr}
		return c.Render(http.StatusOK, "Dashboard", data)
	case 2:
		//start of session
		store := newCookieStore()
		session, _ := store.Get(c.Request(), SESSION_ID)
		session.Values["Privilege"] = PrivilegeDB
		session.Save(c.Request(), c.Response())
		//privilegeUser := fmt.Sprintf("%s", PrivilegeDB)
		//log.Println("your privilege :", privilegeUser)
		//end of session
		return c.Render(http.StatusOK, "Dashboard", nil)
	case 3:
		//start of session
		store := newCookieStore()
		session, _ := store.Get(c.Request(), SESSION_ID)
		session.Values["Privilege"] = PrivilegeDB
		session.Save(c.Request(), c.Response())
		//privilegeUser := fmt.Sprintf("%s", PrivilegeDB)
		//log.Println("your privilege :", privilegeUser)
		//end of session
		return c.Render(http.StatusOK, "Dashboard", nil)
	}

	defer db.Close()
	return c.Render(http.StatusOK, "Login", nil)

}

func ListUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	//end of session checking
	if s == "1" {

		db := database.Connect()
		Query, Err := db.Query("SELECT Id,Username, Firstname, Lastname, Address, Privilege, Status,CreateAt " +
			"FROM users ORDER BY Id ASC")
		if Err != nil {
			log.Println("Show data failed")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}

		Each := Models.Users{}
		Res := []Models.Users{}

		for Query.Next() {
			var id, privilege, status int //variable from struct users
			var username, firstname, lastname, address, create_at string
			Scanning := Query.Scan(&id, &username, &firstname, &lastname, &address, &privilege, &status, &create_at)
			if Scanning != nil {
				log.Println("scanning process failed")
				//return c.Render(http.StatusInternalServerError, "error_500", nil)
			}

			Each.Id = id
			Each.Username = username
			Each.Firstname = firstname
			Each.Lastname = lastname
			Each.Address = address
			Each.Privilege = privilege
			Each.Status = status
			Each.CreateAt = create_at

			Res = append(Res, Each)
		}
		defer Query.Close()
		return c.Render(http.StatusOK, "list-user", Res)
	}

	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	return c.Render(http.StatusOK, "Login", nil)
}

func ViewUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		db := database.Connect()
		IdRequestView, _ := strconv.Atoi(c.Param("id"))
		var id int
		var username, firstname, lastname, address string
		Err := db.QueryRow("SELECT Id, Username, Firstname,Lastname, Address FROM users where Id = ?", IdRequestView).
			Scan(&id, &username, &firstname, &lastname, &address)

		if Err != nil {
			log.Println("View user failed")
			//return c.Render(http.StatusInternalServerError, "error_500", nil)
		}

		var nameImageRequest string
		imageUserRequest := db.QueryRow("SELECT Name FROM images WHERE Status = ? AND UserId = ?", 1, IdRequestView).
			Scan(&nameImageRequest)

		if imageUserRequest != nil {
			log.Println(IdRequestView)
			log.Println("View image user failed")
			//return c.Render(http.StatusInternalServerError, "error_500", nil)
		}

		dataUser := Models.Users{
			Id:        IdRequestView,
			Username:  username,
			Firstname: firstname,
			Lastname:  lastname,
			Address:   address,
		}

		dataImage := Models.Images{
			NameImage: nameImageRequest,
		}

		Res := M{
			"Response":      dataUser,
			"ResponseImage": dataImage,
		}
		defer db.Close()
		return c.Render(http.StatusOK, "View-User", Res)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking
	return c.Render(http.StatusOK, "Login", nil)
}

func EditUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {

		db := database.Connect()
		idRequestEdit, _ := strconv.Atoi(c.Param("id"))

		var username, password, firstname, lastname, address, nameImage string
		errQuery := db.QueryRow("SELECT Username, Firstname, Lastname, Address, Password FROM users WHERE Id = ?", idRequestEdit).
			Scan(&username, &firstname, &lastname, &address, &password)
		if errQuery != nil {
			log.Println("err inserting edit user data..")
			return c.Render(http.StatusInternalServerError, "list-user", nil)
		}

		errQuery = db.QueryRow("SELECT Name FROM images WHERE Status = ? AND UserId = ?", 1, idRequestEdit).Scan(&nameImage)
		if errQuery != nil {
			log.Println("err inserting edit image data")
			return c.Render(http.StatusInternalServerError, "list-user", nil)
		}

		resUserDetails := Models.Users{
			Id:        idRequestEdit,
			Username:  username,
			Firstname: firstname,
			Lastname:  lastname,
			Address:   address,
			Password:  password,
		}
		resImage := Models.Images{NameImage: nameImage}

		responses := resUserDetails
		responseImage := resImage
		data := M{"response": responses, "responseImage": responseImage}
		defer db.Close()
		return c.Render(http.StatusOK, "Edit-User", data)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking
	return c.Render(http.StatusOK, "Dashboard", nil)
}

func StoreUpdateUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {

		db := database.Connect()
		Id, _ := strconv.Atoi(c.Param("id"))
		Username := c.FormValue("Username")
		Firstname := c.FormValue("Firstname")
		Lastname := c.FormValue("Lastname")
		Password, _ := HashPassword(c.FormValue("Password")) //generate password
		Address := c.FormValue("Address")
		UpdateAt := time.Now().Format("01-02-2006")

		Rows, ErrPrepare := db.Prepare("UPDATE users SET Username=?,Firstname=?,Lastname=?,Address=?,Password=?, UpdateAt=? WHERE Id =?")
		if ErrPrepare != nil {
			log.Println("update users failed")
			//return c.Render(http.StatusInternalServerError, "error_500", nil)
		}
		defer Rows.Close()

		_, ErrExec := Rows.Exec(Username, Firstname, Lastname, Address, Password, UpdateAt, Id)
		if ErrExec != nil {
			log.Println("error exec update user")
			//return c.Render(http.StatusInternalServerError, "error_500", nil)
		}

		//start of upload file

		//source
		file, errFile := c.FormFile("imageUser")
		if errFile != nil {
			log.Println("error file")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}

		//read files uploaded
		n := file.Filename
		k := fmt.Sprintf("%s", n) //converting image name to string
		log.Println("namefile", k)

		//get ext file
		e := fmt.Sprintf("%s", filepath.Ext(n))
		log.Println("file extension : ", e)

		//generate name file randomized
		s := GenerateStringFile(15)
		//f := fmt.Sprintf("%s", s)

		src, errSrc := file.Open()
		if errSrc != nil {
			log.Println("error file open")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}
		defer src.Close()

		//set directory file upload
		fileLocation := "./assets/images/"

		//destiny
		dstny, errDstny := os.Create(fileLocation + s + e)
		if errDstny != nil {
			log.Println("error destiny")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}

		//copying file to store on db
		if _, ErrCopy := io.Copy(dstny, src); ErrCopy != nil {
			d := fmt.Sprintf("file %s upload successfully,", file.Filename)
			log.Println(d)
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}
		//end of upload file

		//do inactive status image  1 to 0
		//UpdateAt := time.Now().Format("01-02-2006")
		dataInactivate := "UPDATE images SET Status = ?,UpdateAt = ? WHERE UserId = ?"
		inactivating, errInactivating := db.Prepare(dataInactivate)
		if errInactivating != nil {
			log.Println("error update details image..")
			return c.Render(http.StatusInternalServerError, "Edit-User", nil)
		}

		_, execInactivate := inactivating.Exec(0, UpdateAt, Id)
		if execInactivate != nil {
			log.Println("error update exec details image..")
			return c.Render(http.StatusInternalServerError, "Edit-User", nil)
		}

		//do insert image to image table date/status 1 and name image where userId = Id User
		deleteNewDataUser, updateNewDataUser := "", ""
		dataUpdates := "INSERT INTO images (Id, Name, Status, CreateAt, UpdateAt, DeleteAt, UserId) values (?,?,?,?,?,?,?)"
		insNewUpdate, errInsNewUpdate := db.Prepare(dataUpdates)
		if errInsNewUpdate != nil {
			log.Println("error insert update image..")
			return c.Render(http.StatusInternalServerError, "Edit-User", nil)
		}

		//start get last id image
		var idNewDataImage int
		checklastIdImage := db.QueryRow("SELECT  MAX(Id) FROM images").Scan(&idNewDataImage)
		if checklastIdImage != nil {
			log.Println("err get last id")
			return c.Render(http.StatusInternalServerError, "list-user", nil)
		}

		dataLastIdImage := Models.Images{
			Id: idNewDataImage,
		}

		_ = M{"response": dataLastIdImage}
		lastIdImage := idNewDataImage + 1
		//ond of get last id image

		nameOfFile := s + e
		statusOfUser, creatAtNewDataUser := 1, time.Now().Format("01-02-2006")
		_, newUpdateExec := insNewUpdate.Exec(lastIdImage, nameOfFile, statusOfUser, creatAtNewDataUser,
			updateNewDataUser, deleteNewDataUser, Id)
		if newUpdateExec != nil {
			log.Println("error insert exec image..")
			return c.Render(http.StatusInternalServerError, "Edit-User", nil)
		}

		defer db.Close()
		log.Println("update user successfully")
		return c.Render(http.StatusOK, "list-user", nil)
	}

	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking
	return c.Render(http.StatusOK, "Dashboard", nil)
}

func AddUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		return c.Render(http.StatusOK, "Add-User", nil)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking

	return c.Redirect(http.StatusOK, "/admin/dashboard")
}

func StoreAddUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		//end of session checking
		db := database.Connect()

		//start of upload file
		//source
		file, errFile := c.FormFile("imageUser")
		if errFile != nil {
			log.Println("error file")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}

		//read files uploaded
		n := file.Filename
		k := fmt.Sprintf("%s", n) //converting name image to string
		log.Println("namefile", k)

		//get ext file
		e := fmt.Sprintf("%s", filepath.Ext(n))
		log.Println("file extension : ", e)

		//generate name file
		s := GenerateStringFile(15)
		//f := fmt.Sprintf("%s", s)

		src, errSrc := file.Open()
		if errSrc != nil {
			log.Println("error file open")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}
		defer src.Close()

		//set dir upload
		fileLocation := "./assets/images/"

		//destiny
		dstny, errDstny := os.Create(fileLocation + s + e)
		if errDstny != nil {
			log.Println("error destiny")
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}

		//copying file to store on db
		if _, ErrCopy := io.Copy(dstny, src); ErrCopy != nil {
			d := fmt.Sprintf("file %s upload successfully,", file.Filename)
			log.Println(d)
			return c.Render(http.StatusInternalServerError, "Add-User", nil)
		}

		//end of upload file

		Username := c.FormValue("Username")
		formatReg := "^[a-zA-Z_.0-9]{0,30}$"
		errMatch, _ := regexp.MatchString(formatReg, Username)
		if errMatch != true {
			log.Println("regex didn't match")
			responseReg := "You may just type like alphanumeric underscore and dot"
			data := M{"responseRegex": responseReg}
			return c.Render(http.StatusInternalServerError, "Add-User", data)
		}
		fmt.Println(errMatch)

		if Username == "" {
			res := "Username cannot be empty"
			data := M{"responseUsername": res}
			return c.Render(http.StatusInternalServerError, "Add-User", data)
		}

		Password, _ := HashPassword("12345678") //default password 12345678
		Firstname := c.FormValue("Firstname")
		Lastname := c.FormValue("Lastname")
		Address := c.FormValue("Address")
		Status, Privilege := "1", "3"
		CreateAt, UpdateAt, DeleteAt := time.Now().Format("01-02-2006"), "", ""

		//Begin of validating unique username
		ErrCheck := db.QueryRow("SELECT Username FROM users WHERE Username = ?", Username).Scan(&Username)
		if ErrCheck == nil {
			log.Println("error duplicate username")
			response := "Username already exist!"
			data := M{"errorUpdate": response}
			defer db.Close()
			return c.Render(http.StatusInternalServerError, "Add-User", data)
		}
		//End of validating unique username

		//must be get last id insert new id
		var maxIdUser int
		checklastId := db.QueryRow("SELECT  MAX(Id) FROM users").Scan(&maxIdUser)
		if checklastId != nil {
			log.Println("err get last id")
			return c.Render(http.StatusInternalServerError, "list-user", nil)
		}

		dataLastId := Models.Users{
			Id: maxIdUser,
		}
		_ = M{"response": dataLastId}
		log.Println(maxIdUser)
		lastIdUser := maxIdUser + 1

		//Begin of creating user
		stmt, Errstmt := db.Prepare("insert users(Id, Username, Password, Firstname, Lastname, Address,Privilege, " +
			"Status, CreateAt, UpdateAt, DeleteAt) values (?,?,?,?,?,?,?,?,?,?,?)")
		if Errstmt != nil {
			log.Println("error store new user")
			defer db.Close()
			return c.Render(http.StatusInternalServerError, "Create-User", nil)
		}

		_, ErrExec := stmt.Exec(lastIdUser, Username, Password, Firstname, Lastname, Address, Privilege, Status, CreateAt, UpdateAt, DeleteAt)
		if ErrExec != nil {
			log.Println("error exec create user")
			return c.Render(http.StatusInternalServerError, "Create-User", nil)
		}

		//start of inserting data file uploadede
		uploading, errupload := db.Prepare("INSERT images(Id, Name, Status, CreateAt, UpdateAt, DeleteAt,UserId) values (?,?,?,?,?,?,?)")
		if errupload != nil {
			log.Println("error preparing inserting name file")
			defer db.Close()
			return c.Render(http.StatusInternalServerError, "Create-User", nil)
		}

		nameOfFile := s + e
		Status = "1"

		//get last id of image
		//======================
		var maxIdImage int
		checklastIdImage := db.QueryRow("SELECT  MAX(Id) FROM images").Scan(&maxIdImage)
		if checklastIdImage != nil {
			log.Println("err get last id")
			return c.Render(http.StatusInternalServerError, "list-user", nil)
		}

		dataLastIdImage := Models.Users{
			Id: maxIdImage,
		}
		_ = M{"response": dataLastIdImage}
		log.Println(maxIdImage)
		lastIdImage := maxIdImage + 1
		//get last id of image
		//==========================

		_, errExecUpload := uploading.Exec(lastIdImage, nameOfFile, Status, CreateAt, UpdateAt, DeleteAt, lastIdUser)
		if errExecUpload != nil {
			log.Println("error exec inserting name file")
			return c.Render(http.StatusInternalServerError, "Create-User", nil)
		}
		//end of inserting name of file uploadede

		defer stmt.Close()
		//End of creating user

		log.Print("user created successfully")
		//response := "user created successfully"
		//xdata := M{"resUserCreated": response}
		//error saat pasaing data karna bentrok dg maps dari Controller llist user,
		//solusinya sebelum di alihin ke page list user info konfirm sukkses, dan beri pilihan ke page daftar user

		return c.Render(http.StatusOK, "list-user", nil)
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	return c.Render(http.StatusOK, "list-user", nil)
}

func DeleteUser(c echo.Context) error {

	//start of get session id
	store := newCookieStore()
	session, _ := store.Get(c.Request(), SESSION_ID)
	s := fmt.Sprintf("%s", session.Values["Privilege"])
	if s == "0" {
		return c.Render(http.StatusOK, "Login", nil)
	}
	if s == "1" {
		db := database.Connect()
		Id, _ := strconv.Atoi(c.Param("id"))

		Query, ErrDelete := db.Prepare("DELETE FROM  users WHERE Id=?")
		if ErrDelete != nil {
			log.Println("delete failed")
			//return c.Render(http.StatusInternalServerError, "error_500", nil)
		}

		_, ErrExec := Query.Exec(Id)
		if ErrExec != nil {
			log.Println("delete failed")
			//return c.Render(http.StatusInternalServerError, "error_500", nil)
		}

		defer db.Close()
		return c.Redirect(http.StatusTemporaryRedirect, "/admin/user/list")
	}
	if s == "2" {
		return c.Render(http.StatusOK, "dashboard-staff-", nil)
	}
	if s == "3" {
		return c.Render(http.StatusOK, "dashboard-member", nil)
	}
	//end of session checking
	return c.Redirect(http.StatusTemporaryRedirect, "/Login")
}

func UploadCsvFileUser(c echo.Context) error {
	//upload
	//reader
	file, errFile := c.FormFile("csvFile")
	if errFile != nil {
		log.Println("error file")
		return c.Render(http.StatusInternalServerError, "/admin/user/list", nil)
	}

	//read files uploaded
	readFilename := file.Filename
	filename := fmt.Sprintf("%s", readFilename) //converting image name to string
	log.Println("namefile", filename)

	//get ext file
	ext := fmt.Sprintf("%s", filepath.Ext(readFilename))
	log.Println("file extension : ", ext)

	src, errSrc := file.Open()
	if errSrc != nil {
		log.Println("error file open")
		return c.Redirect(http.StatusInternalServerError, "/user/list")
	}
	defer src.Close()

	//set directory file upload
	fileLocation := "./assets/users_import/"

	f := time.Now().Format("01-02-2006_03-04-05-PM")
	namefileImport := "file-users_" + f + ext

	//destiny
	dstny, errDstny := os.Create(fileLocation + namefileImport)
	if errDstny != nil {
		log.Println("error destiny")
		return c.Redirect(http.StatusInternalServerError, "/user/list")
	}

	//copying file to store on db
	if _, ErrCopy := io.Copy(dstny, src); ErrCopy != nil {
		log.Println("error copying file")
		return c.Redirect(http.StatusInternalServerError, "/user/list")
	}
	//lookUpPath := dstny + errDstny
	xlsx, errSrc := excelize.OpenFile(fileLocation + namefileImport)
	if errSrc != nil {
		log.Println("error file open")
		return c.Render(http.StatusInternalServerError, "Add-User", nil)
	}
	log.Print("preparing to inserting massal..")

	//get lookup into file import
	s := "users_import"
	rows := make([]M, 0)
	dd := len(xlsx.GetRows(s)) + 1
	log.Print("count of rows sheet users :\n", dd)
	for i := 2; i < dd; i++ {
		row := M{
			"Username":  xlsx.GetCellValue(s, fmt.Sprintf("A%d", i)),
			"Password":  xlsx.GetCellValue(s, fmt.Sprintf("B%d", i)),
			"Firstname": xlsx.GetCellValue(s, fmt.Sprintf("C%d", i)),
			"Lastname":  xlsx.GetCellValue(s, fmt.Sprintf("D%d", i)),
			"Address":   xlsx.GetCellValue(s, fmt.Sprintf("E%d", i)),
			"Privilege": xlsx.GetCellValue(s, fmt.Sprintf("F%d", i)),
			"Status":    xlsx.GetCellValue(s, fmt.Sprintf("G%d", i)),
		}
		rows = append(rows, row)
	}
	for _, x := range rows {
		Username := x["Username"]
		Password := x["Password"].(string)
		hashedPass, _ := HashPassword(Password)
		Firstname := x["Firstname"]
		Lastname := x["Lastname"]
		Address := x["Address"]
		Privilege := x["Privilege"]
		Status := x["Status"]

		db := database.Connect()
		importUser := "INSERT INTO users (Username, Password, Firstname, Lastname, Address, Privilege, Status, CreateAt) " +
			"VALUES (?,?,?,?,?,?,?,?)"
		insImportUser, errImportUser := db.Prepare(importUser)
		if errImportUser != nil {
			log.Println("error inserting into user")
		}
		CreateAt := time.Now().Format("01-02-2006")
		_, errImportUserExec := insImportUser.Exec(Username, hashedPass, Firstname, Lastname, Address, Privilege, Status, CreateAt)
		if errImportUserExec != nil {
			log.Println("error execing query into user")
		}

		defer db.Close()
	}
	//fmt.Printf("%v \n", rows)
	return c.String(http.StatusTemporaryRedirect, "uploading success.. (100%)")
}

func Layout(c echo.Context) error {
	return c.Render(http.StatusOK, "layouts", nil)
}

// ############################################     end of code     ############################################
