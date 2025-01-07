<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register','emailverify', 'verifyEmail', 'forgotpassword', 'changepassword']]);
    }

    /**
     * Login API
     */
    public function login(Request $request) {
        $validator = Validator::make($request->all(),
            [
                'email'=>'required|string|email',
                'password'=>'required|string'
            ]
        );

        if($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $credentials = $request->only('email', 'password');

        $token = Auth::attempt($credentials);

        if(!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'unauthorized'
            ], 401);
        }

        $user = Auth::user();
        return response()->json([
            'status' => 'success',
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer'
            ]
        ]);
    }

    /**
     * Register API
     */
    public function register(Request $request, JWTAuth $jwtAuth) {
        $validator = Validator::make($request->all(),[
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'gender' => 'required|string',
            'role' => 'required|string'
        ]);

        if($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'gender' => $request->gender,
            'role' => $request->role,
        ]);

        //$token = $user->createToken('authToken', ['gender' => $request->gender, 'role' => $request->role])->plainTextToken;

        //$user = User::find($userId);

        $customClaims = [
            'gender' => $request->gender,
            'role' => $request->role,
        ];

        $token = $jwtAuth->claims($customClaims)->fromUser($user);

        return response()->json([
            'status' => 'success',
            'message' => 'User Registered Successfully',
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    /**
     * User Detail API
     */
    public function userDetails() {
        return response()->json(auth()->user());
    }

    /**
     * Send email verification link
     */
    public function emailverify($email) {
        $user = User::where('email', $email)->first();

        if($user) {
            $user->emailverification();
            return response()->json(['status'=>'success','message' => 'Verify Your Email Address' ]);
        } else {
            return response()->json(['status'=>'error', 'message' => 'User Not Found']);
        }
    }

    /**
     * confirm email verification status
     */
    public function verifyEmail(Request $request) {
        $token = $request->input('token');

        $user = User::where('email_verification_token', $token)->first();

        if($user) {
            if($user->email_verified_at === null) {
                $user->update([
                    'email_verified_at' => now(),
                    'email_verification_token' => null,
                    'email_verified' => 1,
                ]);
                return response()->json(['status'=>'success', 'message'=> 'Email verified successfully']);
            } else {
                return response()->json(['status'=> 'error', 'message' => 'Email already verified']);
            }
        } else {
            return response()->json(['status'=> 'error', 'message'=>'Invalid token']);
        }
    }

    /**
     * forget password
     */
    public function forgotpassword(Request $request) {
        $email = $request->email;
        $user = User::where('email',$email)->first();
        if($user) {
            $password = Str::random(10);
            Mail::send([],[],function($message) use($email, $password) {
                $message->to($email)
                        ->subject("Reset Password")
                        ->html("<p>Your New Password is</p><br/>".$password);
            });
            User::where('email', $email)->update(['password'=>Hash::make($password)]);
            return response()->json(['status'=>'success','message'=>'New Password send in your email']);
        } else {
            return response()->json(['status'=>'error', 'message'=> 'User Not Found']);
        }
    }

    /**
     * Change password
     */
    public function changepassword(Request $request) {
        $userId = $request->userId;
        $currentPassword = $request->cpassword;
        $newPassword = $request->npassword;

        $user = User::find($userId);

        if($user) {
            if(Hash::check($currentPassword, $user->password)) {
                User::where('id', $userId)->update(['password'=>Hash::make($newPassword)]);
                return response()->json(['status'=>'success', 'message'=> 'Password Change Successfully']);
            } else {
                return response()->json(['status'=>'error','message'=>'Current Password Not Match']);
            }
        } else {
            return response()->json(['status'=>'error', 'message'=>'User Not Found']);
        }
    }
}
