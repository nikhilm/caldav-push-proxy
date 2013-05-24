package main

import (
	"encoding/json"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
	"encoding/xml"
)

type MultiStatusResponse struct {
    XMLName xml.Name `xml:"multistatus"`
    Response struct {
        Propstat struct {
            Prop struct {
                Getctag string `xml:"getctag"`
            } `xml:"prop"`
        } `xml:"propstat"`
    }`xml:"response"`
}

var gRedis redis.Conn
var pushClient http.Client
var calendarClient http.Client

func notifyEndpoint(endpoint string) {
	log.Println("Notifying", endpoint)
	body := fmt.Sprintf("version=%d", uint64(time.Now().Unix()))
	r, err := http.NewRequest("PUT", endpoint, strings.NewReader(body))
	if err != nil {
		log.Println(err)
		return
	}

	r.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}

	_, err = pushClient.Do(r)
	if err != nil {
		log.Println(err)
		return
	}
}

func propfind(username, passwd, url string) (string, error) {
	body := `<?xml version="1.0" encoding="utf-8" ?> 
    <D:propfind xmlns:D="DAV:"> 
      <D:prop xmlns:CS="http://calendarserver.org/ns/"> 
        <CS:getctag/>
      </D:prop>
    </D:propfind>`

    r, err := http.NewRequest("PROPFIND", url, strings.NewReader(body))
    if err != nil {
        return "", err
    }

    r.SetBasicAuth(username, passwd)
    r.Header["Content-Type"] = []string{"application/xml"}
    r.Header["Depth"] = []string{"0"}
    resp, reqErr := calendarClient.Do(r)
    if reqErr != nil {
        return "", reqErr
    }

    defer resp.Body.Close()
    decoder := xml.NewDecoder(resp.Body)
    v := MultiStatusResponse{}
    parseErr := decoder.Decode(&v)
    if parseErr != nil {
        return "", parseErr
    }

    return v.Response.Propstat.Prop.Getctag, nil
}

// Username uniquely identifies a user.
// A User has 2 endpoints, one for updates and one for errors.
// A User also has calendars
// Nothing stops the same device from having multiple users.
type Username string // caldav-user:Username::Domain

func username(username string, domain string) Username {
	return Username(fmt.Sprintf("caldav-user::%s::%s", username, domain))
}

// Mapping from Username -> password.
// Should be kept strictly in memory and not logged.
type Credentials map[Username]string

var gCredentials Credentials

type AccountModel struct {
	Domain         string `json:"domain"`
	User           string `json:"user"`
	Password       string `json:"password"`
	UpdateEndpoint string `json:"updateEndpoint"`
	ErrorEndpoint  string `json:"errorEndpoint"`
}

type RemoteCalendarModel struct {
	Url       string `json:"url"`
	SyncToken string `json:"syncToken"` // Actually http://calendarserver.org/ns/getctag.
}

type CalendarModel struct {
	Remote RemoteCalendarModel `json:"remote"`
}

type RegistrationRequest struct {
	User      AccountModel    `json:"user"`
	Calendars []CalendarModel `json:"calendars"`
}

func notifyErrorToUser(u Username) {
	errorEndpoint, err := redis.String(gRedis.Do("HGET", u, "errorEndpoint"))
	if err == nil {
		notifyEndpoint(errorEndpoint)
	} else {
		log.Println("Error %s notifying Error to User %s", err, u)
	}
}

/*
* When the server shuts down, it loses the credentials of all users.
* It uses the known error endpoints to request clients to tell it the passwords again.
 */
func askClientsToRegisterAgain() {
	users, err := redis.Strings(gRedis.Do("KEYS", "caldav-users:*"))
	if err == nil {
		for _, user := range users {
			notifyErrorToUser(Username(user))
		}
	}
}

// Redis storage is as a hash with base key the username.
// Each hash entry is:
// updateEndpoint -> string
// errorEndpoint -> string
// <cal1 url> -> ctag
// <cal2 url> -> ctag
// ...
func redisHashFromRequest(req *RegistrationRequest) []interface{} {
	var arr []interface{}

	arr = append(arr, "updateEndpoint", req.User.UpdateEndpoint)
	arr = append(arr, "errorEndpoint", req.User.ErrorEndpoint)

	for _, calendar := range req.Calendars {
		arr = append(arr, calendar.Remote.Url, calendar.Remote.SyncToken)
	}

	return arr
}

func mapFromRedisHash(redisHash []string) map[string]string {
	if len(redisHash)%2 != 0 {
		log.Fatal("Invalid redisHash (odd length) %s", redisHash)
	}

	entries := make(map[string]string)
	for i := range redisHash {
		if i%2 != 0 {
			continue
		}

		entries[redisHash[i]] = redisHash[i+1]
	}

	return entries
}

func registerHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		resp.Write([]byte("Not a post request"))
		log.Println("Not a post request")
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte("Could not access body of request"))
		log.Println("Could not access body")
		return
	}

	request := new(RegistrationRequest)
	err = json.Unmarshal(body, request)

	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		resp.Write([]byte("Could not unmarshal body, "))
		log.Println(err)
		return
	}

	username := username(request.User.User, request.User.Domain)
	gCredentials[username] = request.User.Password

	redisHash := redisHashFromRequest(request)
	if len(redisHash)%2 != 0 {
		log.Fatal("Invalid hash from request %s", redisHash)
	}

	var args []interface{}
	args = append(args, string(username))
	args = append(args, redisHash...)
	if _, saveErr := gRedis.Do("HMSET", args...); saveErr != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		resp.Write([]byte("Could not save to database"))
		log.Println("Error saving request")
	}
}

func checkCalendars(u Username, passwd, updateEndpoint, errorEndpoint string, calendars map[string]string) {
	usernameParts := strings.Split(string(u), "::")
	if len(usernameParts) != 3 {
		log.Panic("Bad username %s", u)
	}

	httpUsername := usernameParts[1]

	anyCalendarChanged := false
	for calendar, syncToken := range calendars {
		calendarUrl := fmt.Sprintf("%s%s", usernameParts[2], calendar)

		log.Println("Checking", httpUsername, calendarUrl, syncToken)

		newSyncToken, err := propfind(httpUsername, passwd, calendarUrl)
		if err != nil {
			log.Println("Error propfinding", err)
			notifyEndpoint(errorEndpoint)
			// If any calendar fails, no point continuing
			return
		}

		if newSyncToken != syncToken {
			log.Println(calendarUrl, "changed")
			anyCalendarChanged = true
			// update our cache
			if _, saveErr := gRedis.Do("HSET", u, calendar, newSyncToken); saveErr != nil {
				log.Println("Error updating syncToken to", newSyncToken, "for", u, calendarUrl)
			}
		}
	}

	if anyCalendarChanged {
		notifyEndpoint(updateEndpoint)
	}
}

// Of course this is not the right way to do constant time polling.
func pollCalendars() {
	for {
		time.Sleep(5 * time.Second) // FIXME Minute
		entries, err := redis.Strings(gRedis.Do("KEYS", "caldav-user:*"))
		if err != nil {
			log.Println("Error fetching keys")
			continue
		}

		for _, entry := range entries {
			passwd, found := gCredentials[Username(entry)]
			if !found {
				log.Println("Password not found for %s", entry)
				continue
			}

			redisHash, getAllErr := redis.Strings(gRedis.Do("HGETALL", entry))
			if getAllErr != nil {
				log.Println("Could not get hash entry for %s", entry)
				continue
			}

			hash := mapFromRedisHash(redisHash)
			updateEndpoint := hash["updateEndpoint"]
			errorEndpoint := hash["errorEndpoint"]
			delete(hash, "updateEndpoint")
			delete(hash, "errorEndpoint")

			go checkCalendars(Username(entry), passwd, updateEndpoint, errorEndpoint, hash)
		}
	}
}

func main() {
	// Check that redis is working.
	var err error
	if gRedis, err = redis.Dial("tcp", "localhost:6379"); err != nil {
		log.Println(err == nil)
		log.Fatal("Error connecting to Redis. %s", err)
	}

	gCredentials = make(Credentials)

	go askClientsToRegisterAgain()
	go pollCalendars()

	http.HandleFunc("/register", registerHandler)
	log.Println("Starting...")
	http.ListenAndServe("nikhilism.com:8009", nil)
}
