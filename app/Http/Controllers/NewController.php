<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class NewController extends Controller
{

    public function newMethod(Request $request)
    {
        return response()->json([
            'status' => 'success',
            'message' => 'This is a new route'
        ]);
    }
}
