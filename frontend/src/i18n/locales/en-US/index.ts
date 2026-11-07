import accounts from "./accounts";
import audit from "./audit";
import baseline from "./baseline";
import cleanup from "./cleanup";
import common from "./common";
import dashboard from "./dashboard";
import drift from "./drift";
import inventory from "./inventory";
import login from "./login";
import newTicket from "./newTicket";
import status from "./status";
import sync from "./sync";
import ticketDetail from "./ticketDetail";
import tickets from "./tickets";
import users from "./users";

// One slice per page keeps the translation work reviewable; they are merged
// into a single resource tree below.
export default {
  ...common,
  ...dashboard,
  ...drift,
  ...tickets,
  ...ticketDetail,
  ...inventory,
  ...newTicket,
  ...sync,
  ...accounts,
  ...audit,
  ...baseline,
  ...cleanup,
  ...users,
  ...login,
  ...status,
};
