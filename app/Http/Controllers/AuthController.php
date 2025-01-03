<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
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
}
