import { useEffect, useState } from "react";
import { StatusBar } from "expo-status-bar";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { OnboardingScreen } from "./src/screens/Onboarding";
import { WalletScreen } from "./src/screens/Wallet";
import { RecoverScreen } from "./src/screens/Recover";
import { loadAccount } from "./src/lib/storage";
import type { RootStackParamList } from "./src/navigation";

const Stack = createNativeStackNavigator<RootStackParamList>();

export default function App() {
  const [initialRoute, setInitialRoute] = useState<keyof RootStackParamList | null>(null);

  useEffect(() => {
    (async () => {
      const acct = await loadAccount();
      setInitialRoute(acct ? "Wallet" : "Onboarding");
    })();
  }, []);

  if (!initialRoute) return null;

  return (
    <NavigationContainer>
      <StatusBar style="auto" />
      <Stack.Navigator initialRouteName={initialRoute}>
        <Stack.Screen
          name="Onboarding"
          component={OnboardingScreen}
          options={{ headerShown: false }}
        />
        <Stack.Screen name="Wallet" component={WalletScreen} options={{ title: "vouch" }} />
        <Stack.Screen name="Recover" component={RecoverScreen} options={{ title: "Recover" }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
