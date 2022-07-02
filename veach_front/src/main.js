import { createApp } from "vue";
// import Vue from 'vue'
import App from "./App.vue";
import store from "./store";
import userState from "./store/user-state";
import router from "./router";
import "./assets/css/nucleo-icons.css";
import "./assets/css/nucleo-svg.css";
import MaterialDashboard from "./material-dashboard";
const appInstance = createApp(App);
appInstance.config.performance = true
appInstance.use(store);
appInstance.use(userState);
appInstance.use(router);
appInstance.use(MaterialDashboard);
appInstance.mount("#app");
