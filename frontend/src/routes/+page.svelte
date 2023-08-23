<script>
    import WithUnsealed from "../components/WithUnsealed.svelte";
    import {onMount} from "svelte";
    import {fetchLoginCheck} from "../utils/dataFetching.js";
    import Login from "../components/login/Login.svelte";
    import AdminMain from "../components/admin/AdminMain.svelte";
    import {saveXsrfToken} from "../utils/helpers.js";
    import Principal from "../components/principal/Principal.svelte";
    import Draggable from "../components/Draggable.svelte";
    import UserMain from "../components/user/UserMain.svelte";
    import NoAccess from "../components/NoAccess.svelte";
    import {storePrincipal} from "../stores/principal.js";

    let isLoggedIn;
    let principal;

    onMount(() => {
        checkLogin();
    });

    async function checkLogin() {
        let res = await fetchLoginCheck();
        const body = await res.json();
        if (res.ok) {
            if (body.xsrf) {
                const xsrf = body.xsrf;
                saveXsrfToken(xsrf);
                // the reload is necessary to clear caches from the localstorage
                window.location.reload();
            } else {
                principal = body.principal;
                storePrincipal.set(body.principal);
                isLoggedIn = true;
            }
        } else {
            isLoggedIn = false;
        }
    }
</script>

<WithUnsealed>
    {#if isLoggedIn}
        {#if principal}
            <Draggable>
                <Principal bind:principal/>
            </Draggable>
        {/if}

        {#if principal.isAdmin}
            <AdminMain/>
        {:else if principal.isUser}
            <UserMain/>
        {:else}
            <NoAccess/>
        {/if}
    {:else}
        <Login/>
    {/if}
</WithUnsealed>
