package Captcha::reCAPTCHA::V2;

use strict;
use warnings;
use HTML::Tiny;
use HTTP::Tiny;
use Carp;
use JSON;

# ABSTRACT: Perl implementation to reCAPTCHA API version 2

# VERSION

sub new {
    my $class = shift;
    $class = ref $class if ref $class;
    my $self = bless {}, $class;

    # Initialize the user agent object
    $self->{ua}   = HTTP::Tiny->new(
        agent => 'Captcha::reCAPTCHA::V2/'.
            ($Captcha::reCAPTCHA::V2::VERSION || 0) . ' (Perl)'
    );

    $self->{html} = HTML::Tiny->new();

    $self->{widget_api} = 'https://www.google.com/recaptcha/api.js?'.
                            'onload=onloadCallback&render=explicit';

    $self->{verify_api} = 'https://www.google.com/recaptcha/api/siteverify';

    $self->{element_id} = 'recaptcha_';

    return $self;
}

sub _extract_key {
    my ( $self, $key ) = @_;
    return substr( $key, 0, 10 );
}

sub _get_grecaptcha {
    my( $self, $sitekey, $options ) = @_;

    $options ||= {};

    my $html = $self->{html};

    my $json_options = $html->json_encode({ sitekey => $sitekey, %$options });

    return $html->script(
        { type => 'text/javascript' },
        'var onloadCallback = function(){'.
            "grecaptcha.render('" . $self->{element_id} . $self->_extract_key( $sitekey ) .
            "'," . $json_options . ");".
        '};'
    );
}

sub get_html {
    my ( $self, $pubkey, $options ) = @_;

    if( !defined $pubkey ){
        croak 'Public key is required to use reCAPTCHA';
    }

    unless( ref $options eq "HASH" ){
        croak 'Options must be a reference to hash';
    }

    my $script = $self->_get_grecaptcha( $pubkey, $options );

    my $html = $self->{html};

    return join(
        '',
        $script,
        "\n",
        $html->script(
            {
                type => 'text/javascript',
                src  =>  $self->{widget_api}
            }
        ),
        "\n",
        $html->tag(
            'div',
            { id => $self->{element_id} . $self->_extract_key( $pubkey ) }
        ),
    );

}

sub check_answer {
    my ( $self, $secretkey, $response, $remoteip ) = @_;

    if ( !defined $secretkey ){
        croak 'Secret key is required to verify reCAPTCHA';
    }

    if ( !defined $response ){
        croak 'Response from user is required to verify reCAPTCHA';
    }

    my $params = {
        secret    => $secretkey,
        response  => $response,
    };

    $params->{remoteip} = $remoteip if defined $remoteip;

    my $res = $self->{ua}->post_form(
        $self->{verify_api},
        $params
    );

    if( $res->{success} ){
        my $content = decode_json $res->{content};
        if( $content->{success} ){
            return { is_valid => 1 };
        } else {
            return { is_valid => 0, error => $content->{'error-codes'}->[0] };
        }

    }
}

1;

=head1 SYNOPSIS

Captcha::reCAPTCHA::V2 provides easy way to use reCAPTCHA version 2
in your web application.

    use Captcha::reCAPTCHA::V2;

    my $rc = Captcha::reCAPTCHA::V2->new;

    # Get widget in HTML to display the reCAPTCHA
    my $widget = $rc->get_html('public key');

    # Forward HTML to render in template
    return template 'feedback', {
        recaptcha => $widget
    };

    # Display in template
    [% recaptcha %]

    # Verify user's response
    my $response  = param('g-recaptcha-response');
    my $result    = $rc->check_answer('private key', $response);

    if ($result->{is_valid}){
        # Good
    } else {
        # Bad
    }

=head1 SUBROUTINES/METHODS

=head2 get_html

Generates HTML for rendering reCAPTCHA widget which should be displayed in template.
Arguments:

=head3 C<$publickey>

B<(Required)> The site's public key provided by API

=head3 C<$options>

A reference to hash containing parameters to set the appearance and behavior
of reCAPTCHA widget, L<see grecaptcha.render parameters|https://developers.google.com/recaptcha/docs/display#render_param>.
The paremeters can contain these following keys:

=over

=item C<theme>

The color theme of the of the widget. Possible values are 'dark' and 'light'.

=item C<type>

The type of the reCAPTCHA to serve. Possible values are 'audio' and 'image'.

=item C<size>

The size of the widget. Possible values are 'compact' and 'normal'.

=back

Example:

    # In route handler
    my $widget = $rc->get_html('public key', { theme => 'dark', type => 'audio' });

    template 'index' => {
        recaptcha => $widget
    };

    # In template
    [% recaptcha %]

=head2 check_answer

Verifies user's response to a reCAPTCHA challenge to check if the answer is correct.
Arguments:

=head3 C<$privatekey>

B<(Required)> The site's private key provided by API

=head3 C<$response>

B<(Required)> Response string retrieved from the submitted form field
C<g-recaptcha-response>.

=head3 C<$remoteip>

IP address of the user.

Returns a reference to a hash containing two fields: C<is_valid> and C<error>.

Example:

    my $response  = param('g-recaptcha-response');
    my $result    = recaptcha_check('private key', $response);

    if( $result->{is_valid} ){
        print "The answer is correct!";
    }
    else {
        print $result->{error};
    }

=head1 SEE ALSO

=for :list

* L<Captcha::reCAPTCHA>

* L<Google reCAPTCHA API Reference|https://www.google.com/recaptcha/intro/index.html/>

=head1 ACKNOWLEDGEMENTS

Based on Andy Armstrong's a perl implementation of the reCAPTCHA API version 1
(Captcha::reCAPTCHA).

=cut
