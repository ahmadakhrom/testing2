package main

import (
	"Testing/Controller"
	_ "Testing/Models"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/unrolled/secure"
	"html/template"
	"io"
	"net/http"
)

//for usage templates
// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {

	// Add global methods if data is a map
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	//error handling to 404 page
	echo.NotFoundHandler = func(c echo.Context) error {
		error404 := "<p style='font-family:monospace; margin: 0 auto; text-align: center;' >" +
			"<strong style='font-size:5rem;padding-top:10px;'>Oops 404!</strong>" +
			"<br>That page can’t be found." +
			"<br><a href='/' style:'text-decoration:none;'>back to home page</a></p>"
		return c.HTML(http.StatusNotFound, error404)
	}

	//inisialisasi framework echo
	e := echo.New()

	//running templating
	Map := template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseFiles(

			//Public page
			"Views/Public/Login.html",
			"Views/public/testing.html",
			"Views/public/testing2.html",

			//User page
			"Views/User/Dashboard.html",
			"Views/User/Dashboard-staff.html",
			"Views/User/Dashboard-member.html",
			"Views/User/Create-User.html",
			"Views/User/list-user.html",
			"Views/User/View-User.html",
			"Views/User/Edit-User.html",
			"Views/User/Add-User.html",

			//corona
			"Views/corona/data.html",
			"Views/corona/data-global.html",

			//books page
			"Views/books/books.html",

			//Template page
			//"Views/Templates/Footer.html",
			//"Views/Templates/Header.html",
			//"Views/Templates/Header-Brand.html",
			//"Views/Templates/Sidebar.html",
			//"Views/Templates/layouts.html",

			//"Views/Templates2/footer.tpl",
			"Views/Templates2/header.html",
			"Views/Templates2/sidebar.html",
			"Views/Templates2/footer.html",

			//error page
			"Views/Error-Page/error500.html",

			//running templating
		)).Funcs(Map),
	}
	e.Renderer = renderer

	//securing access web server
	secureWebServ := secure.New(secure.Options{
		BrowserXssFilter:        true,
		ContentTypeNosniff:      true,
		FrameDeny:               true,
		CustomFrameOptionsValue: "SAMEORIGIN",
		AllowedHosts:            []string{"localhost:9000", "www.google.com"},
	})
	e.Use(echo.WrapMiddleware(secureWebServ.Handler)) //wrap handler to avoid memory leaks

	//set cors
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))

	//set logging
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method} | uri=${uri} | status=${status}\n",
	}))

	//set recover
	e.Use(middleware.Recover())

	//gzip
	e.Use(middleware.Gzip())

	//route login
	e.GET("/", Controller.Login)
	e.POST("/login", Controller.Login)
	e.GET("/logout", Controller.Logout)
	e.POST("/dashboard", Controller.Dashboard) //xxxxxxxxxxxx
	e.GET("/layouts", Controller.Layout)

	//routes admin
	a := "/admin"
	e.GET(a+"/dashboard", Controller.Dashboards)
	e.GET(a+"/user/list", Controller.ListUser)
	e.GET(a+"/user/:id/profile", Controller.ViewUser)
	e.GET(a+"/user/:id/edit", Controller.EditUser)
	e.GET(a+"/user/:id/delete", Controller.DeleteUser)
	e.GET(a+"/user/add", Controller.AddUser)
	e.POST(a+"/user/update/:id", Controller.StoreUpdateUser)
	e.POST(a+"/user/store", Controller.StoreAddUser)
	e.POST(a+"/user/upload-file", Controller.UploadCsvFileUser)

	e.GET("/dashboard/staff", Controller.DashboardStaff)
	e.GET("/dashboard/member", Controller.DashboardMember)

	//testing routes
	e.GET("/corona/api/data", Controller.Corona)
	e.GET("/corona/api/global", Controller.CoronaGlobal)
	e.GET("/corona/api/testing", Controller.Employee)
	//e.GET("/testing2", Controller.TestPage2)

	//for usage static files
	e.Static("/static", "assets")
	e.Static("/upload", "images")

	//port server //with auto tls
	e.Logger.Fatal(e.Start(":9000"))
}

