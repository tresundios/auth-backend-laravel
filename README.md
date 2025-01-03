composer create-project --prefer-dist laravel/laravel my-laravel-app "10.*"

php artisan migrate

composer require php-open-source-saver/jwt-auth

php artisan vendor:publish --provider="PHPOpenSourceSaver\JWTAuth\Providers\LaravelServiceProvider"

php artisan jwt:secret

npm create vite@latest auth-frontend -- --template react

cd auth-frontend

npm install react@18 react-dom@18

npm install

npm run dev

npm list react react-dom

php artisan make:controller AuthController

php artisan migrate:fresh

npm install web-vitals
