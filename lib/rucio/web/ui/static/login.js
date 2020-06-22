$(document).ready(function() {
    if (window.location.href.includes('/ui/')) {
        $('#login_form').attr('action', '/ui/login');
    }

    display_spinner = function() {
        $('#loader').html('<div class="row"><div class="large-1 large-centered columns"><img src="/media/spinner.gif"></div></div><br>');
    }
});
