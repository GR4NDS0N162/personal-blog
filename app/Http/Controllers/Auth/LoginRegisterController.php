<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginRegisterController extends Controller
{
    /**
     * Instantiate a new LoginRegisterController instance.
     */
    public function __construct()
    {
        $this->middleware('guest')->except([
            'logout',
            'dashboard',
        ]);
    }

    /**
     * Display a registration form.
     *
     * @return View|Factory
     */
    public function register(): View|Factory
    {
        return view('auth.register');
    }

    /**
     * Store a new user.
     *
     * @param Request $request
     *
     * @return Response
     */
    public function store(Request $request): Response
    {
        $request->validate([
            'name'     => 'required|string|max:250',
            'email'    => 'required|email|max:250|unique:users',
            'password' => 'required|min:8|max:250|confirmed',
        ]);

        User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $credentials = $request->only('email', 'password');
        Auth::attempt($credentials);
        $request->session()->regenerate();
        return redirect()->route('dashboard')
            ->withSuccess('You have successfully registered & logged in!');
    }

    /**
     * Display a login form.
     *
     * @return View|Factory
     */
    public function login(): View|Factory
    {
        return view('auth.login');
    }

    /**
     * Authenticate the user.
     *
     * @param Request $request
     *
     * @return Response|RedirectResponse
     */
    public function authenticate(Request $request): Response|RedirectResponse
    {
        $credentials = $request->validate([
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
            return redirect()->route('dashboard')
                ->withSuccess('You have successfully logged in!');
        }

        return back()->withErrors([
            'email' => 'Your provided credentials do not match in our records.',
        ])->onlyInput('email');
    }

    /**
     * Display a dashboard to authenticated users.
     *
     * @return View|Factory|RedirectResponse
     */
    public function dashboard(): View|Factory|RedirectResponse
    {
        if (Auth::check()) {
            return view('auth.dashboard');
        }

        return redirect()->route('login')
            ->withErrors([
                'email' => 'Please login to access the dashboard.',
            ])->onlyInput('email');
    }

    /**
     * Log out the user from application.
     *
     * @param Request $request
     *
     * @return Response
     */
    public function logout(Request $request): Response
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect()->route('login')
            ->withSuccess('You have logged out successfully!');
    }
}
