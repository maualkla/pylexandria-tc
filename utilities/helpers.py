## utilities.helpers

import os, base64, re, rsa

class Helpers:
    ## return String (lenght)
    def randomString(_length):
        try:
            print(" >> helpers.randomString() helper.")
            import random, string
            output_str = ''.join(random.choice(string.ascii_letters) for i in range(_length))
            return output_str
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## return userId
    def idGenerator(_length):
        try:
            print(" >> idGenerator() helper.")
            userId = Helpers.currentDate()
            userId = Helpers.randomString(2) + userId + Helpers.randomString(_length)
            return userId
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Base64 encode
    def b64Encode(_string):
        try:
            print(" >> b64Encode() helper.")
            _out = base64.b64encode(_string.encode('utf-8'))
            _r_out = str(_out, "utf-8")
            return _r_out
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Base64 decode
    def b64Decode(_string):
        try:
            print(" >> b64Decode() helper.")
            _out = base64.b64decode(_string).decode('utf-8')
            return _out
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}

    ## Current date: 
    def currentDate():
        try:
            print(" >> currrentDate() helper.")
            from datetime import datetime
            _now = datetime.now()
            _now = _now.strftime("%d%m%YH%M%S")
            return _now
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}
    
    ## Current date: 
    def currentDateTime():
        try:
            print(" >> currrentDateTime() helper.")
            from datetime import datetime
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            return current_time
        except Exception as e:
            return {"status": "An error Occurred", "error": str(e)}
        
    ## Get URL parameters:
    ## Function receive a string like this "limit:10;username:maualkla;active:true"
    ## Has to return a dict containing {"parameter" : "value"}
    def splitParams(_query):
        try:
            print(" >> splitParams() helper.")
            if int(_query.count(":")) == int(_query.count(";"))+1:
                _x = 0
                _params_in_query = _query.count(":")
                _response = {}
                while _x < _params_in_query:
                    _index = _query.find(";")
                    if _index == -1:
                        _temp = _query[0:]
                    else: 
                        _temp = _query[0:_index]
                    _index_2 = _temp.find(":")
                    _response[_temp[0:_index_2]] = _temp[_index_2+1:]
                    _query = _query[_index+1:]
                    _x += 1
                return _response
            else:
                return {"status":"params_query_not_valid"}
        except Exception as e:
            print(" (!) Exception in splitParameters(): ")
            print(str(e))
            return False
    
    ## Validates a password based on the following criteria:
    ## - At least 12 characters long
    ## - Contains at least one uppercase letter
    ## - Contains at least one lowercase letter
    ## - Contains at least one number
    ## - Contains at least one special character
    ##
    ## Args:
    ##    password: The password to validate.
    ##
    ## Returns:
    ##    True if the password is valid, False otherwise.
    def validatePasswordFormat(_string, _logging):
        try:
            print(" >> validatePassword() helper.")
            ##pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{12,}$" ## PP@ssw0rd!234
            ##return Helpers.validatePattern(_string, pattern, _logging)
            return True if len(_string) >= 10 else False
        
        except Exception as e:
            print(" (!) Exception in validatePassword(): ")
            print(str(e))
            return False
        
    ## Validate email format
    def validateEmailFormat(_string, _logging):
        try:
            print(" >> validateEmailFormat() helper.")
            pattern = r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$"
            return Helpers.validatePattern(_string, pattern, _logging)
        
        except Exception as e:
            print(" (!) Exception in validateEmailFormat(): ")
            print(str(e))
            return False

    ## Validate date format.
    def validateDateFormat(_string, _logging):
        try:
            print(" >> validateDateFormat() helper.")
            pattern = r"^(0[1-9]|[12][0-9]|3[01])\.(0[1-9]|1[012])\.(19|20)\d\d$"
            return Helpers.validatePattern(_string, pattern, _logging)
        
        except Exception as e:
            print(" (!) Exception in validateDateFormat(): ")
            print(str(e))
            return False

    ## Validate phone number format
    def validatePhoneFormat(_string, _logging):
        try:
            print(" >> validatePhoneFormat() helper.")
            pattern = r"^\d{10}$"
            return Helpers.validatePattern(_string, pattern, _logging)
        
        except Exception as e:
            print(" (!) Exception in validatePhoneFormat(): ")
            print(str(e))
            return False
    
    ## Validate postal code format.
    def validatePostalCodeFormat(_string, _countryCode, _logging):
        try:
            print(" >> validatePhoneFormat() helper.")
            if _countryCode == "MX": 
                pattern = r"^\d{5}$"
            elif _countryCode == "US": 
                pattern = r"^\d{5}(-\d{4})?$"
            elif _countryCode == "DE":
                pattern = r"^\d{5}$"
            else: 
                pattern = r"^\d{5}$"
            return Helpers.validatePattern(_string, pattern, _logging)
        
        except Exception as e:
            print(" (!) Exception in validatePhoneFormat(): ")
            print(str(e))
            return False

    ## Validate pattern
    def validatePattern(_string, _pattern, _logging):
        try: 
            if _logging: print(" >> validatePattern() helper. String: " + str(_string) + " Pattern: " + str(_pattern) + ".")
            match = re.match(_pattern, _string)
            return bool(match)
        
        except Exception as e:
            print(" (!) Exception in validatePattern(): ")
            print(str(e))
            return False

