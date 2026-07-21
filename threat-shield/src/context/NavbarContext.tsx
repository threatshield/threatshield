import React, { createContext, useContext, useState } from 'react';

interface NavbarContextValue {
  isCollapsed: boolean;
  toggleCollapse: () => void;
  /** When true, pages can force the navbar to be hidden (e.g. the 404 page). */
  navbarHidden: boolean;
  setNavbarHidden: (hidden: boolean) => void;
}

const NavbarContext = createContext<NavbarContextValue>({
  isCollapsed: false,
  toggleCollapse: () => {},
  navbarHidden: false,
  setNavbarHidden: () => {},
});

export const useNavbar = () => useContext(NavbarContext);

export const NavbarProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [navbarHidden, setNavbarHidden] = useState(false);
  const toggleCollapse = () => setIsCollapsed(v => !v);
  return (
    <NavbarContext.Provider value={{ isCollapsed, toggleCollapse, navbarHidden, setNavbarHidden }}>
      {children}
    </NavbarContext.Provider>
  );
};
