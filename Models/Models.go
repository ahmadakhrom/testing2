package Models

type Users struct {
	No        int    `json:"no"`
	Id        int    `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Address   string `json:"address"`
	Privilege int    `json:"privilege"`
	Status    int    `json:"status"`
	CreateAt  string `json:"create_at"`
	UpdateAt  string `json:"update_at"`
	DeleteAt  string `json:"delete_at"`
}

type Images struct {
	Id        int    `json:"id"`
	NameImage string `json:"nameImage"`
	Status    int    `json:"status"`
	CreateAt  string `json:"create_at"`
	UpdateAt  string `json:"update_at"`
	DeleteAt  string `json:"delete_at"`
	UserId    string `json:"user_id"`
}

type Employee struct {
	Status string           `json:"status"`
	Data   []DetailEmployee `json:"data"`
}

type DetailEmployee struct {
	ID             string `json:"id"`
	EmployeeName   string `json:"employee_name"`
	EmployeeSalary string `json:"employee_salary"`
	EmployeeAge    string `json:"employee_age"`
	ProfileImage   string `json:"profile_image"`
}


type CoronaIndo struct{
	Name      string `json:"name"`
	Positif   string `json:"positif"`
	Sembuh    string `json:"sembuh"`
	Meninggal string `json:"meninggal"`
}

type CoronaGlobalRes struct {
	Attributes string `json:"attributes"`
}

type attributes struct {
	Country_Region string `json:"country_region"`
}
