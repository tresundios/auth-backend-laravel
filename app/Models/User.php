<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Mail;
use Laravel\Sanctum\HasApiTokens;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use Illuminate\Support\Str;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'gender',
        'role',
        'email_verified_at',
        'email_verification_token',
        'email_verified',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [
            'gender' => $this->gender,
            'role' => $this->role,
            'email' => $this->email,
            'name' => $this->name,
        ];
    }

    public function emailVerification() {
        $email = $this->email;
        $token = Str::random(40);
        $user = User::where('email', $email)->first();

        $user->update(['email_verification_token' => $token]);

        $link = env('FRONT_URL').'email-verification?token='.$token;
        Mail::send([],[],function($message) use($email,$link) {
            $message->to($email)
                    ->subject("Verify Your Email Address")
                    ->html("<p>Verify your Email</p><br/><a href='".$link."'>Verify Email Address</a>");
        });
        return $link;
    }
}
