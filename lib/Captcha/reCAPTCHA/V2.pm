package Captcha::reCAPTCHA::V2;

use strict;
use warnings;

use Carp;
use HTML::Tiny;
use HTTP::Tiny;
use JSON;

# ABSTRACT: A Perl implementation of reCAPTCHA API version 2

# VERSION

=head1 SYNOPSIS

Captcha::reCAPTCHA::V2 enables you to integrate reCAPTCHA version 2 into your
web application.

    use Captcha::reCAPTCHA::V2;

    # Create a new instance of Captcha::reCAPTCHA::V2
    my $rc = Captcha::reCAPTCHA::V2->new;

    # Get HTML code to display the reCAPTCHA
    my $rc_html = $rc->get_html('public key');

    # Verify user's response
    my $result = $rc->check_answer('private key', $response);

    if ($result->{is_valid}){
        # Good
    } else {
        # Bad
        $error = $result->{error};
    }

=method new

Creates a new instance of Captcha::reCAPTCHA::V2.

    my $rc = Captcha::reCAPTCHA::V2->new;

=cut

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
    my ($self, $key) = @_;
    return substr($key, 0, 10);
}

sub _get_grecaptcha {
    my ($self, $sitekey, $options) = @_;

    $options ||= {};

    my $html = $self->{html};

    my $json_options = $html->json_encode({ sitekey => $sitekey, %$options });

    return $html->script(
        { type => 'text/javascript' },
        'var onloadCallback = function(){'.
            "grecaptcha.render('" . $self->{element_id} . $self->_extract_key($sitekey) .
            "'," . $json_options . ");".
        '};'
    );
}

=method get_html

Returns the HTML code for rendering the reCAPTCHA widget.

    my $html = $rc->get_html('public key', { theme => 'dark' });

Parameters:

=over 4

=item * C<$publickey>

B<(Required)> The site's public key provided by API

=item * C<$options>

A reference to a hash of options that affect the appearance and behavior of the
reCAPTCHA widget. Available options:

=over

=item * C<theme>

The color theme of the widget. Possible values are C<'dark'> and C<'light'>.

=item * C<type>

The type of the captcha to serve. Possible values are C<'audio'> and
C<'image'>.

=item * C<size>

The size of the widget. Possible values are C<'compact'> and C<'normal'>.

=back

See also: <grecaptcha.render parameters|https://developers.google.com/recaptcha/docs/display#render_param>.

=cut

sub get_html {
    my ($self, $pubkey, $options) = @_;

    if (!defined $pubkey) {
        croak 'Public key is required to use reCAPTCHA';
    }

    unless (ref $options eq "HASH") {
        croak 'Options must be a reference to hash';
    }

    my $script = $self->_get_grecaptcha($pubkey, $options);

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
            { id => $self->{element_id} . $self->_extract_key($pubkey) }
        ),
    );

}

=head2 check_answer

Verifies the user's response.

    my $result = $rc->check_answer('private key', $response);

    if ($result->{is_valid}) {
        # ...
    }

Parameters:

=over 4

=item * C<$privatekey>

B<(Required)> The site's private key provided by API

=item * C<$response>

B<(Required)> Response string retrieved from the submitted form field
C<g-recaptcha-response>.

=item * C<$remoteip>

IP address of the user.

=back

Returns a reference to a hash containing two fields: C<is_valid> and C<error>.

=cut

sub check_answer {
    my ($self, $secretkey, $response, $remoteip) = @_;

    if (!defined $secretkey) {
        croak 'Secret key is required to verify reCAPTCHA';
    }

    if (!defined $response) {
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

    if ($res->{success}) {
        my $content = decode_json $res->{content};
        if ($content->{success}){
            return { is_valid => 1 };
        } else {
            return { is_valid => 0, error => $content->{'error-codes'}->[0] };
        }

    }
}

=head1 SEE ALSO

=for :list

* L<Captcha::reCAPTCHA>

* L<Google reCAPTCHA API Reference|https://www.google.com/recaptcha/intro/index.html/>

=head1 ACKNOWLEDGEMENTS

Based on Andy Armstrong's a perl implementation of the reCAPTCHA API version 1
(Captcha::reCAPTCHA).

=cut

1;
