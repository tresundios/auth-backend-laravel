<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\NewController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::controller(AuthController::class)->group(function() {
    Route::post('register', 'register');
    Route::post('login', 'login');
    Route::get('userdetail', 'userDetails');
    Route::post('emailverify', 'emailverify');
    Route::post('verify-email', 'verifyEmail');
    Route::post('forgotpassword', 'forgotpassword');
    Route::post('changepassword', 'changepassword');
});

// Routes with JWT authentication
Route::middleware('auth:api')->group(function () {
    Route::controller(NewController::class)->group(function() {
        Route::get('new-route', 'newMethod');
        // Add more routes as needed
    });
});


// // Independent route with JWT authentication
// Route::middleware('auth:api')->post('/protected-route', function () {
//     $user = JWTAuth::parseToken()->authenticate();
//     return response()->json(['message' => 'You accessed a protected route!', 'user' => $user]);
// });

// // Another independent route
// Route::middleware('auth:api')->get('/user-info', function () {
//     $user = JWTAuth::parseToken()->authenticate();
//     return response()->json(['user' => $user]);
// });

// // Or use controller methods for more complex logic
// Route::middleware('auth:api')->get('/another-protected-route', [YourController::class, 'someMethod']);
