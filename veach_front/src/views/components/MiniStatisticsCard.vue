<template>
  <div class="card mb-2" :class="directionReverse ? reverseDirection : ''">
    <div class="card-header p-3 pt-2">
      <div class="pt-1" :class="isRTL ? 'text-end' : 'text-start'">
        <p class="text-sm mb-0 text-capitalize">{{ title.text }}</p>
        <h4 class="mb-0">{{ title.value }}</h4>
      </div>
    </div>
    <hr class="dark horizontal my-0" />
    <div class="card-footer p-3" :class="isRTL ? 'text-end' : 'text-start'">
      <!--  eslint-disable-next-line vue/no-v-html -->
      <p class="mb-0" v-html="detail"></p>
    </div>
  </div>
</template>

<script>
import { mapState } from "vuex";
export default {
  name: "MiniStatisticsCard",
  data() {
    return {
      reverseDirection: "flex-row-reverse justify-content-between",
    };
  },
  props: {
    title: {
      type: Object,
      required: true,
      text: String,
      value: [Number, String],
    },
    detail: {
      type: String,
      default: "",
    },
    icon: {
      type: Object,
      required: true,
      name: String,
      color: String,
      background: String,
      default: () => ({
        color: "text-white",
        background: "success",
      }),
    },
    directionReverse: {
      type: Boolean,
      default: false,
    },
  },
  computed: {
    ...mapState(["isRTL"]),
  },
};
</script>
