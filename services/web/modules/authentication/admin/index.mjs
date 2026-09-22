import SSOAdminRouter from './app/src/SSOAdminRouter.mjs'

const AdminModule = {
  name: 'admin',
  router: {
    apply(webRouter) {
      SSOAdminRouter.apply(webRouter)
    },
  },
}

export default AdminModule
