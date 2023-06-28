# springboot-security-authentication-authorization-with-token


# Generate token: 
	# Http: POST 
	# URL: http://localhost:8080/user/token
	# Request: 
	  {
	      "userName": "nath1",
	      "password": "dev"
	  }

# Call API using token:
	 # Http: GET 
	 # URL: http://localhost:8080/product/name/asdf
	 # Header attribute 
	   Authorization: <enter generator token here>

 JWT expires in 2 mints observe that after 2 mints , this is configurable
