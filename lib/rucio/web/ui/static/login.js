$(document).ready(function(){
	display_spinner = function () {
		$('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div><br>');
	}

	validate_credentials = function (username, password) {
		r.validate_credentials({
			username: username,
			password: password,
			success: function(data) {
				console.log('Success');
			},
			error: function(jqXHR, textStatus, errorThrown) {
	            console.log('Error');
	            console.log(jqXHR);
	            console.log(errorThrown);
	            console.log(textStatus);
	            $('#loader').html('<center><h2>Invalid</h2></center>');
	        } 
		});
	};
});