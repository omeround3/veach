import { createRouter, createWebHistory } from "vue-router";
import Dashboard from "../views/Dashboard.vue";
import Tables from "../views/Tables.vue";
import Billing from "../views/Billing.vue";
import RTL from "../views/Rtl.vue";
import Notifications from "../views/Notifications.vue";
import Profile from "../views/Profile.vue";
import SignIn from "../views/SignIn.vue";
import SignUp from "../views/SignUp.vue";
import userState from "@/store/user-state";

const routes = [
  {
    path: "/",
    name: "/",
    redirect: "/dashboard",
    meta: {
      requiresAuth: true
    },
    children: [
      {
        path: "/tables",
        name: "Tables",
        component: Tables,
      },
      {
        path: "/billing",
        name: "Billing",
        component: Billing,
      },
      {
        path: "/rtl-page",
        name: "RTL",
        component: RTL,
      },
      {
        path: "/notifications",
        name: "Notifications",
        component: Notifications,
      },
      {
        path: "/profile",
        name: "Profile",
        component: Profile,
      },
    ]
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
  {
    path: "/sign-up",
    name: "SignUp",
    component: SignUp,
  },
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
  const user = userState
  if (to.meta.requiresAuth) {
    // this route requires auth, check if logged in
    // if not, redirect to login page.
    console.log(`isLogged: ${user.getters.isLoggedIn}`);
    if (!user.getters.isLoggedIn) {
      next({ name: 'SignIn' })
    } else {
      next() // go to wherever I'm going
    }
  } else {
    next() // does not require auth, make sure to always call next()!
  }
})


export default router;
