import { createRouter, createWebHistory } from "vue-router";
import Dashboard from "../views/Dashboard.vue";
import Tables from "../views/Tables.vue";
import Billing from "../views/Billing.vue";
import RTL from "../views/Rtl.vue";
import Notifications from "../views/Notifications.vue";
import Profile from "../views/Profile.vue";
import SignIn from "../views/SignIn.vue";
// import SignUp from "../views/SignUp.vue";
import store from "@/store/index";

const routes = [
  {
    path: "/",
    name: "/",
    redirect: "/dashboard",
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/:id",
    name: "Tables",
    component: Tables,
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/billing",
    name: "Billing",
    component: Billing,
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/rtl-page",
    name: "RTL",
    component: RTL,
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/notifications",
    name: "Notifications",
    component: Notifications,
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/settings",
    name: "Settings",
    component: Profile,
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/dashboard",
    name: "Dashboard",
    component: Dashboard,
    meta: {
      requiresAuth: true
    },
  },
  {
    path: "/sign-in",
    name: "SignIn",
    component: SignIn,
  },
  // {
  //   path: "/sign-up",
  //   name: "SignUp",
  //   component: SignUp,
  // },
];

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes,
  linkActiveClass: "active",
  // scrollBehavior(to, from, savedPosition) {
  //   return savedPosition || { left: 0, top: 0 };
  // },
});

router.beforeEach((to, from, next) => {
  if (to.meta.requiresAuth) {
    // this route requires auth, check if logged in
    // if not, redirect to login page.
    console.log(`isLogged: ${store.getters.isLoggedIn}`);
    if (!store.getters.isLoggedIn) {
      next({ name: 'SignIn' })
    } else {
      next() // go to wherever I'm going
    }
  } else {
    next() // does not require auth, make sure to always call next()!
  }
})


export default router;
